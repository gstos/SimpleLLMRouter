package server

import (
	"bufio"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/health"
)

type seenReq struct {
	method, path, query, body string
	header                    http.Header
}

func passSetup(t *testing.T, upstream http.HandlerFunc) (http.Handler, func() []seenReq) {
	h, seen, _ := passServer(t, upstream)
	return h, seen
}

func passServer(t *testing.T, upstream http.HandlerFunc) (http.Handler, func() []seenReq, *Server) {
	t.Helper()
	var mu sync.Mutex
	var seen []seenReq
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, seenReq{r.Method, r.URL.Path, r.URL.RawQuery, string(b), r.Header.Clone()})
		mu.Unlock()
		if upstream != nil {
			upstream(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(up.Close)
	cfg := &config.Config{Providers: []config.Provider{
		{Name: "oc", BaseURL: up.URL + "/zen/go/v1", Auth: config.AuthPassthrough, SessionHeader: "X-Opencode-Session"},
		{Name: "plain", BaseURL: up.URL + "/v1", Auth: config.AuthPassthrough},
		{Name: "native", BaseURL: up.URL + "/v1"},
	}}
	cfg.ApplyDefaults()
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	s.Seal(cfg) // passthrough needs no master key
	return s.Handler(), func() []seenReq { mu.Lock(); defer mu.Unlock(); return append([]seenReq{}, seen...) }, s
}

func passDo(h http.Handler, method, target, body string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPassthroughForwardsUnchanged(t *testing.T) {
	h, seen := passSetup(t, nil)
	w := passDo(h, "POST", "/provider/plain/messages?beta=true", `{"model":"m"}`,
		"Authorization", "Bearer client-own-key", "X-Api-Key", "anthropic-key", "Anthropic-Version", "2023-06-01")
	if w.Code != 200 || w.Body.String() != `{"ok":true}` || w.Header().Get("X-Router-Provider") != "plain" {
		t.Fatalf("response %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	r := seen()[0]
	if r.method != "POST" || r.path != "/v1/messages" || r.query != "beta=true" || r.body != `{"model":"m"}` {
		t.Fatalf("forwarded %+v", r)
	}
	if r.header.Get("Authorization") != "Bearer client-own-key" || r.header.Get("X-Api-Key") != "anthropic-key" ||
		r.header.Get("Anthropic-Version") != "2023-06-01" {
		t.Fatalf("client headers not passed: %v", r.header)
	}
	if r.header.Get("X-Forwarded-For") != "" || r.header.Get("X-Opencode-Session") != "" {
		t.Fatalf("unexpected headers: %v", r.header)
	}

	passDo(h, "GET", "/provider/plain/models", "")
	passDo(h, "GET", "/provider/plain/v1/", "")
	if r := seen()[2]; r.path != "/v1/v1/" {
		t.Fatalf("trailing slash lost: %s", r.path)
	}
	if r := seen()[1]; r.method != "GET" || r.path != "/v1/models" {
		t.Fatalf("GET forwarded as %+v", r)
	}
}

func TestPassthroughOnlyConfiguredProviders(t *testing.T) {
	h, seen := passSetup(t, nil)
	// Without a router key, managed and unknown providers look the same: 401.
	for _, target := range []string{"/provider/native/chat/completions", "/provider/unknown/x", "/provider/", "/provider/http:"} {
		if w := passDo(h, "POST", target, "{}"); w.Code != 401 {
			t.Errorf("%s: %d", target, w.Code)
		}
	}
	if len(seen()) != 0 {
		t.Fatal("request reached an upstream")
	}
}

func TestPassthroughCannotClimbAboveBaseURL(t *testing.T) {
	_, seen, s := passServer(t, nil)
	r := httptest.NewRequest("GET", "/provider/plain/models", nil)
	r.URL.Path = "/provider/plain/a/../../../../admin" // straight to the handler: no mux cleaning
	s.direct(httptest.NewRecorder(), r)
	if got := seen(); len(got) != 1 || got[0].path != "/v1/admin" {
		t.Fatalf("forwarded to %+v", got)
	}
}

func TestPassthroughSession(t *testing.T) {
	h, seen := passSetup(t, nil)
	session := func(i int) string { return seen()[i].header.Get("X-Opencode-Session") }

	// Anthropic /messages: system field + growing messages.
	passDo(h, "POST", "/provider/oc/messages", `{"system":"S","messages":[{"role":"user","content":"Hi"}]}`)
	passDo(h, "POST", "/provider/oc/messages", `{"system":"S","messages":[{"role":"user","content":"Hi"},{"role":"assistant","content":"Yo"},{"role":"user","content":"More"}]}`)
	// Another chat.
	passDo(h, "POST", "/provider/oc/messages", `{"system":"S","messages":[{"role":"user","content":"Other"}]}`)
	// OpenAI /responses with instructions + string input.
	passDo(h, "POST", "/provider/oc/responses", `{"instructions":"I","input":"Q"}`)
	passDo(h, "POST", "/provider/oc/responses", `{"instructions":"I","input":"Q"}`)
	// No conversation, and the client's own header.
	passDo(h, "GET", "/provider/oc/models", "")
	passDo(h, "GET", "/provider/oc/models", "")
	passDo(h, "POST", "/provider/oc/chat/completions", `{"messages":[{"role":"user","content":"x"}]}`, "X-Opencode-Session", "mine")

	if len(session(0)) != 32 || session(0) != session(1) {
		t.Fatalf("growing chat: %q %q", session(0), session(1))
	}
	if session(2) == session(0) {
		t.Fatal("different chats share a session")
	}
	if session(3) != session(4) || session(3) == session(0) {
		t.Fatalf("responses: %q %q", session(3), session(4))
	}
	if len(session(5)) != 32 || session(5) == session(6) {
		t.Fatalf("no-conversation sessions should be random: %q %q", session(5), session(6))
	}
	if session(7) != "mine" {
		t.Fatalf("client session not kept: %q", session(7))
	}
	if seen()[1].body == "" || !strings.Contains(seen()[1].body, "More") {
		t.Fatal("body not forwarded after being read for the session")
	}
}

func TestPassthroughStreams(t *testing.T) {
	release := make(chan struct{})
	h, _ := passSetup(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "data: two\n\n")
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/provider/plain/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line := make(chan string, 1)
	go func() { l, _ := bufio.NewReader(resp.Body).ReadString('\n'); line <- l }()
	select {
	case l := <-line:
		if l != "data: one\n" {
			t.Fatalf("got %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first event not flushed before the stream ended")
	}
	close(release)
}

func TestHealthSkipsPassthroughOnly(t *testing.T) {
	c := health.New([]config.Provider{
		{Name: "pass-only", BaseURL: "http://127.0.0.1:1", Auth: config.AuthPassthrough},
		{Name: "managed-no-key", BaseURL: "http://127.0.0.1:1", Auth: config.AuthManaged},
	}, time.Second, nil)
	res := c.CheckAll(t.Context())
	if len(res) != 1 || res[0].Provider != "managed-no-key" {
		t.Fatalf("%+v", res)
	}
}
