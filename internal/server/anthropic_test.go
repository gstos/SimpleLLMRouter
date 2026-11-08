package server

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/health"
	"github.com/gstos/SimpleLLMRouter/internal/router"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

type anthUpstream struct {
	srv  *httptest.Server
	fail atomic.Int32 // status to fail with; 0 = succeed
	mu   sync.Mutex
	reqs []seenReq
}

func newAnthUpstream(t *testing.T, name string, handler http.HandlerFunc) *anthUpstream {
	u := &anthUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.reqs = append(u.reqs, seenReq{r.Method, r.URL.Path, r.URL.RawQuery, string(b), r.Header.Clone()})
		u.mu.Unlock()
		if st := u.fail.Load(); st != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(int(st))
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`)
			return
		}
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"from `+name+`"}]}`)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *anthUpstream) last() seenReq {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.reqs[len(u.reqs)-1]
}

func anthSetup(t *testing.T, handler http.HandlerFunc) (http.Handler, map[string]*anthUpstream) {
	t.Helper()
	mk, _ := secrets.GenerateKey()
	ci, _ := secrets.New(mk)
	ups := map[string]*anthUpstream{}
	var provs []config.Provider
	for _, n := range []string{"a", "b"} {
		ups[n] = newAnthUpstream(t, n, handler)
		enc, _ := ci.Encrypt("stored-" + n)
		provs = append(provs, config.Provider{Name: n, BaseURL: ups[n].srv.URL + "/v1", APIKey: enc, AuthHeader: "x-api-key", AuthScheme: "none"})
	}
	cfg := &config.Config{
		Providers: provs,
		Models: []config.Model{
			{Name: "claude", Type: config.TypeMessages, Targets: []config.Target{
				{Provider: "a", Model: "claude-a", Priority: 1},
				{Provider: "b", Model: "claude-b", Priority: 2},
			}},
			{Name: "gpt", Targets: []config.Target{{Provider: "a", Model: "gpt-a"}}},
		},
		APIKeys: []config.APIKey{{Name: "full", Hash: auth.Hash(fullKey), Models: []string{"*"}}},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.DecryptSecrets(ci); err != nil {
		t.Fatal(err)
	}
	rt := router.New(cfg, nil)
	srv := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	srv.Update(cfg, rt, health.New(cfg.Providers, time.Second, nil))
	return srv.Handler(), ups
}

func anthDo(h http.Handler, path, body string, hdr ...string) (*httptest.ResponseRecorder, map[string]any) {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

const anthBody = `{"model":"claude","max_tokens":10,"system":"S","messages":[{"role":"user","content":"Hi"}]}`

func TestMessagesRoutedNatively(t *testing.T) {
	h, ups := anthSetup(t, nil)
	w, out := anthDo(h, "/v1/messages", anthBody,
		"X-Api-Key", fullKey, "Anthropic-Version", "2023-06-01", "Anthropic-Beta", "prompt-caching-2024-07-31")
	if w.Code != 200 || w.Header().Get("X-Router-Provider") != "a" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if out["type"] != "message" {
		t.Fatalf("body not relayed: %v", out)
	}
	r := ups["a"].last()
	if r.path != "/v1/messages" || !strings.Contains(r.body, `"model":"claude-a"`) || !strings.Contains(r.body, `"system":"S"`) {
		t.Fatalf("upstream got %+v", r)
	}
	if r.header.Get("X-Api-Key") != "stored-a" || r.header.Get("Anthropic-Version") != "2023-06-01" ||
		r.header.Get("Anthropic-Beta") != "prompt-caching-2024-07-31" {
		t.Fatalf("upstream headers: %v", r.header)
	}

	// count_tokens goes to its own path.
	anthDo(h, "/v1/messages/count_tokens", anthBody, "X-Api-Key", fullKey)
	if p := ups["a"].last().path; p != "/v1/messages/count_tokens" {
		t.Fatalf("count_tokens path %s", p)
	}
}

func TestMessagesFailoverOn529(t *testing.T) {
	h, ups := anthSetup(t, nil)
	ups["a"].fail.Store(529)
	w, _ := anthDo(h, "/v1/messages", anthBody, "X-Api-Key", fullKey)
	if w.Code != 200 || w.Header().Get("X-Router-Provider") != "b" || !strings.Contains(ups["b"].last().body, `"model":"claude-b"`) {
		t.Fatalf("no failover: %d %v", w.Code, w.Header())
	}
	// All down: the last upstream error is relayed in Anthropic's own shape.
	ups["b"].fail.Store(529)
	w, out := anthDo(h, "/v1/messages", anthBody, "X-Api-Key", fullKey)
	if w.Code != 529 || out["type"] != "error" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestMessagesErrorShape(t *testing.T) {
	h, _ := anthSetup(t, nil)
	cases := []struct {
		path, body string
		hdr        []string
		status     int
		errType    string
	}{
		{"/v1/messages", anthBody, nil, 401, "authentication_error"},
		{"/v1/messages", `{"model":"nope","messages":[]}`, []string{"X-Api-Key", fullKey}, 404, "not_found_error"},
		{"/v1/messages", `{"model":"gpt","messages":[]}`, []string{"X-Api-Key", fullKey}, 400, "invalid_request_error"},
		{"/v1/messages", `not json`, []string{"X-Api-Key", fullKey}, 400, "invalid_request_error"},
	}
	for _, c := range cases {
		w, out := anthDo(h, c.path, c.body, c.hdr...)
		e, _ := out["error"].(map[string]any)
		if w.Code != c.status || out["type"] != "error" || e["type"] != c.errType || e["message"] == "" {
			t.Errorf("%s %s: %d %s", c.path, c.body, w.Code, w.Body.String())
		}
	}
	// A messages model on an OpenAI route: OpenAI/OpenRouter shape there.
	w, out := anthDo(h, "/v1/chat/completions", `{"model":"claude","messages":[]}`, "Authorization", "Bearer "+fullKey)
	if e, _ := out["error"].(map[string]any); w.Code != 400 || out["type"] != nil || e["code"] != float64(400) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestMessagesSticky(t *testing.T) {
	key := func(system string, msgs ...string) string {
		var list []map[string]string
		for i, m := range msgs {
			role := "user"
			if i%2 == 1 {
				role = "assistant"
			}
			list = append(list, map[string]string{"role": role, "content": m})
		}
		raw, _ := json.Marshal(list)
		sys, _ := json.Marshal(system)
		k, _ := stickyKey("full", "claude", httptest.NewRequest("POST", "/", nil), map[string]json.RawMessage{"messages": raw, "system": sys})
		return k
	}
	if key("S", "Hi") != key("S", "Hi", "Hello", "More") {
		t.Fatal("growing Anthropic conversation changed its sticky key")
	}
	if key("S1", "Hi") == key("S2", "Hi") {
		t.Fatal("system prompt not part of the sticky key")
	}
}

func TestMessagesStreams(t *testing.T) {
	release := make(chan struct{})
	h, _ := anthSetup(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message_start\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "event: message_stop\n")
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/v1/messages", strings.NewReader(anthBody))
	req.Header.Set("X-Api-Key", fullKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line := make(chan string, 1)
	go func() { l, _ := bufio.NewReader(resp.Body).ReadString('\n'); line <- l }()
	select {
	case l := <-line:
		if l != "event: message_start\n" {
			t.Fatalf("got %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream not flushed through the Anthropic writer")
	}
	close(release)
}
