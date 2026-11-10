package server

import (
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/health"
	"github.com/gstos/SimpleLLMRouter/internal/router"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

const peerClientKey = "sr-client"

// peerHandler builds a router handler from providers and models. Provider
// api_keys may be plaintext here: they are encrypted on the way in.
func peerHandler(t *testing.T, provs []config.Provider, models []config.Model) http.Handler {
	t.Helper()
	mk, _ := secrets.GenerateKey()
	ci, _ := secrets.New(mk)
	for i := range provs {
		if provs[i].APIKey != "" {
			provs[i].APIKey, _ = ci.Encrypt(provs[i].APIKey)
		}
	}
	cfg := &config.Config{
		Providers: provs,
		Models:    models,
		APIKeys:   []config.APIKey{{Name: "client", Hash: auth.Hash(peerClientKey), Models: []string{"*"}}},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.DecryptSecrets(ci); err != nil {
		t.Fatal(err)
	}
	srv := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	srv.Update(cfg, router.New(cfg, nil), health.New(cfg.Providers, time.Second, nil))
	return srv.Handler()
}

func peerPost(h http.Handler, path, body string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+peerClientKey)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const peerChatBody = `{"model":"m","messages":[{"role":"user","content":"hi"}]}`

func TestPeerLocalExternalPeerOrderAndForwarding(t *testing.T) {
	local := newAnthUpstream(t, "local", nil)
	local.fail.Store(503)
	ext := newAnthUpstream(t, "ext", nil)
	ext.fail.Store(500)
	peer := newAnthUpstream(t, "peer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Router-Provider", "inner")
		w.Header().Set("X-Router-Upstream-Model", "qwen-x")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	h := peerHandler(t,
		[]config.Provider{
			{Name: "gpu", BaseURL: local.srv.URL + "/v1", APIKey: "stored-gpu"},
			{Name: "or", BaseURL: ext.srv.URL + "/v1", APIKey: "stored-or", External: true},
			{Name: "router-b", BaseURL: peer.srv.URL + "/v1", Peer: true, Headers: map[string]string{"X-Static": "yes"}},
		},
		[]config.Model{{Name: "m", Targets: []config.Target{
			// Listed out of order: priorities decide.
			{Provider: "router-b", Priority: 3},
			{Provider: "or", Model: "vendor/m", Priority: 2},
			{Provider: "gpu", Model: "m-local", Priority: 1},
		}}},
	)
	w := peerPost(h, "/v1/chat/completions", peerChatBody, "X-Session-Id", "sess-1", "X-Api-Key", "dup-"+peerClientKey)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if local.n() != 1 || ext.n() != 1 || peer.n() != 1 {
		t.Fatalf("hits local=%d ext=%d peer=%d, want 1 each", local.n(), ext.n(), peer.n())
	}
	got := peer.last()
	if got.header.Get("Authorization") != "Bearer "+peerClientKey {
		t.Errorf("peer Authorization = %q, want the client's", got.header.Get("Authorization"))
	}
	if got.header.Get("X-Api-Key") != "dup-"+peerClientKey {
		t.Errorf("peer X-Api-Key = %q", got.header.Get("X-Api-Key"))
	}
	if got.header.Get("X-Session-Id") != "sess-1" || got.header.Get("X-Router-Hop") != "1" || got.header.Get("X-Static") != "yes" {
		t.Errorf("peer headers: %v", got.header)
	}
	if !strings.Contains(got.body, `"model":"m"`) {
		t.Errorf("peer body %s: want the canonical model name", got.body)
	}
	if h := w.Header(); h.Get("X-Router-Provider") != "router-b" || h.Get("X-Router-Upstream-Model") != "m" ||
		h.Get("X-Router-Peer-Provider") != "inner" || h.Get("X-Router-Peer-Model") != "qwen-x" {
		t.Errorf("response headers: %v", h)
	}
	// Non-peer upstreams get their stored key, never the client's.
	for name, up := range map[string]*anthUpstream{"gpu": local, "or": ext} {
		hd := up.last().header
		if hd.Get("Authorization") != "Bearer stored-"+name {
			t.Errorf("%s Authorization = %q, want the stored key", name, hd.Get("Authorization"))
		}
		if hd.Get("X-Api-Key") != "" || hd.Get("X-Router-Hop") != "" || hd.Get("X-Session-Id") != "" {
			t.Errorf("%s got client credentials or hop headers: %v", name, hd)
		}
		for k, vs := range hd {
			for _, v := range vs {
				if strings.Contains(v, peerClientKey) {
					t.Errorf("%s: client key leaked in %s", name, k)
				}
			}
		}
	}
}

func TestInboundHopServedByLocalTargetsOnly(t *testing.T) {
	local := newAnthUpstream(t, "local", nil)
	ext := newAnthUpstream(t, "ext", nil)
	peer := newAnthUpstream(t, "peer", nil)
	provs := func() []config.Provider {
		return []config.Provider{
			{Name: "gpu", BaseURL: local.srv.URL + "/v1"},
			{Name: "or", BaseURL: ext.srv.URL + "/v1", External: true},
			{Name: "rb", BaseURL: peer.srv.URL + "/v1", Peer: true},
		}
	}
	h := peerHandler(t, provs(), []config.Model{{Name: "m", Targets: []config.Target{
		{Provider: "rb", Priority: 1}, {Provider: "or", Priority: 2}, {Provider: "gpu", Priority: 3},
	}}})
	if w := peerPost(h, "/v1/chat/completions", peerChatBody, "X-Router-Hop", "1"); w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if local.n() != 1 || ext.n() != 0 || peer.n() != 0 {
		t.Fatalf("hits local=%d ext=%d peer=%d, want 1/0/0", local.n(), ext.n(), peer.n())
	}

	// Only peer/external targets: 503 in the router's error shape.
	h = peerHandler(t, provs(), []config.Model{
		{Name: "m", Targets: []config.Target{{Provider: "rb", Priority: 1}, {Provider: "or", Priority: 2}}},
		{Name: "claude", Type: config.TypeMessages, Targets: []config.Target{{Provider: "rb", Priority: 1}, {Provider: "or", Priority: 2}}},
	})
	w := peerPost(h, "/v1/chat/completions", peerChatBody, "X-Router-Hop", "1")
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"code":503`) {
		t.Fatalf("chat: %d %s", w.Code, w.Body.String())
	}
	w = peerPost(h, "/v1/messages", `{"model":"claude","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`, "X-Router-Hop", "1")
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"type":"error"`) || !strings.Contains(w.Body.String(), "overloaded_error") {
		t.Fatalf("messages: %d %s", w.Code, w.Body.String())
	}
	// Authentication still applies.
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(peerChatBody))
	r.Header.Set("X-Router-Hop", "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatalf("no key: %d", rec.Code)
	}
	if ext.n()+peer.n() != 0 {
		t.Fatal("peer/external reached")
	}
}

// Two routers that are each other's peers: a request makes one hop at most.
func TestPeerLoopEndsAfterOneHop(t *testing.T) {
	var aHits, bHits atomic.Int32
	var aH, bH atomic.Value // http.Handler
	count := func(n *atomic.Int32, v *atomic.Value) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n.Add(1)
			v.Load().(http.Handler).ServeHTTP(w, r)
		}))
		t.Cleanup(s.Close)
		return s
	}
	aSrv, bSrv := count(&aHits, &aH), count(&bHits, &bH)
	la := newAnthUpstream(t, "la", nil)
	la.fail.Store(500)
	lb := newAnthUpstream(t, "lb", nil)
	lb.fail.Store(500)
	models := func(local, peer string) []config.Model {
		return []config.Model{{Name: "m", Targets: []config.Target{{Provider: local, Priority: 1}, {Provider: peer, Priority: 2}}}}
	}
	aH.Store(peerHandler(t, []config.Provider{
		{Name: "la", BaseURL: la.srv.URL + "/v1"}, {Name: "b", BaseURL: bSrv.URL + "/v1", Peer: true},
	}, models("la", "b")))
	bH.Store(peerHandler(t, []config.Provider{
		{Name: "lb", BaseURL: lb.srv.URL + "/v1"}, {Name: "a", BaseURL: aSrv.URL + "/v1", Peer: true},
	}, models("lb", "a")))

	post := func() *http.Response {
		req, _ := http.NewRequest("POST", aSrv.URL+"/v1/chat/completions", strings.NewReader(peerChatBody))
		req.Header.Set("Authorization", "Bearer "+peerClientKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := post(); resp.StatusCode < 500 {
		t.Fatalf("both local backends fail, got %d", resp.StatusCode)
	}
	if aHits.Load() != 1 || bHits.Load() != 1 || la.n() != 1 || lb.n() != 1 {
		t.Fatalf("A=%d B=%d la=%d lb=%d, want one each", aHits.Load(), bHits.Load(), la.n(), lb.n())
	}

	// B's local backend recovers: A fails over to B and gets the answer.
	lb.fail.Store(0)
	resp := post()
	if resp.StatusCode != 200 || resp.Header.Get("X-Router-Provider") != "b" || resp.Header.Get("X-Router-Peer-Provider") != "lb" {
		t.Fatalf("failover to peer: %d %v", resp.StatusCode, resp.Header)
	}
	if aHits.Load() != 2 || bHits.Load() != 2 {
		t.Fatalf("A=%d B=%d, want 2 each", aHits.Load(), bHits.Load())
	}
}

func TestPeerHealthUsesHealthzOrigin(t *testing.T) {
	var body atomic.Value
	var status atomic.Int32
	var seen atomic.Value // *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Clone(context.Background()))
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()
	for _, tc := range []struct {
		status  int
		body    string
		healthy bool
	}{
		{200, "ok\n", true},
		{200, "sealed\n", false},
		{500, "ok\n", false},
		{200, "something else", false},
	} {
		status.Store(int32(tc.status))
		body.Store(tc.body)
		p := config.Provider{Name: "rb", BaseURL: srv.URL + "/v1", Peer: true, HealthMethod: "POST"}
		res := health.New([]config.Provider{p}, time.Second, nil).Check(context.Background(), &p)
		if res.Healthy != tc.healthy {
			t.Errorf("%d %q: healthy=%v (%s)", tc.status, tc.body, res.Healthy, res.Error)
		}
		r := seen.Load().(*http.Request)
		if r.Method != "GET" || r.URL.Path != "/healthz" {
			t.Errorf("probe %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Api-Key") != "" {
			t.Errorf("probe sent credentials: %v", r.Header)
		}
	}
}

func TestPeerCAFile(t *testing.T) {
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = io.WriteString(w, "ok\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer peer.Close()
	ca := filepath.Join(t.TempDir(), "peer.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.Certificate().Raw})
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	models := []config.Model{{Name: "m", Targets: []config.Target{{Provider: "rb"}}}}

	trusted := peerHandler(t, []config.Provider{{Name: "rb", BaseURL: peer.URL + "/v1", Peer: true, CAFile: ca}}, models)
	if w := peerPost(trusted, "/v1/chat/completions", peerChatBody); w.Code != 200 {
		t.Fatalf("with ca_file: %d %s", w.Code, w.Body.String())
	}
	p := config.Provider{Name: "rb", BaseURL: peer.URL + "/v1", Peer: true, CAFile: ca}
	if res := health.New([]config.Provider{p}, time.Second, nil).Check(context.Background(), &p); !res.Healthy {
		t.Errorf("health with ca_file: %s", res.Error)
	}

	plain := peerHandler(t, []config.Provider{{Name: "rb", BaseURL: peer.URL + "/v1", Peer: true}}, models)
	if w := peerPost(plain, "/v1/chat/completions", peerChatBody); w.Code != 502 {
		t.Fatalf("without ca_file: %d %s (want a TLS failure)", w.Code, w.Body.String())
	}
	q := config.Provider{Name: "rb", BaseURL: peer.URL + "/v1", Peer: true}
	if res := health.New([]config.Provider{q}, time.Second, nil).Check(context.Background(), &q); res.Healthy {
		t.Error("health without ca_file should fail")
	}
}

// A peer's 401/403/404 is about this client (its key or grant on the peer):
// fail over, but don't put the peer on cooldown for everyone else. A 503 is
// about the peer and does.
func TestPeerClientRefusalSkipsCooldown(t *testing.T) {
	for _, tc := range []struct {
		status   int
		cooldown bool
	}{{401, false}, {403, false}, {404, false}, {503, true}} {
		peer := newAnthUpstream(t, "peer", nil)
		peer.fail.Store(int32(tc.status))
		local := newAnthUpstream(t, "local", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		})
		h := peerHandler(t,
			[]config.Provider{
				{Name: "router-b", BaseURL: peer.srv.URL + "/v1", Peer: true},
				{Name: "cpu", BaseURL: local.srv.URL + "/v1"},
			},
			[]config.Model{{Name: "m", Targets: []config.Target{
				{Provider: "router-b", Priority: 1},
				{Provider: "cpu", Priority: 2},
			}}},
		)
		// Distinct conversations, so sticky routing doesn't pin the second one.
		for i, msg := range []string{"one", "two"} {
			body := `{"model":"m","messages":[{"role":"user","content":"` + msg + `"}]}`
			if w := peerPost(h, "/v1/chat/completions", body); w.Code != 200 {
				t.Fatalf("%d, request %d: status %d", tc.status, i, w.Code)
			}
		}
		want := 2 // tried first both times
		if tc.cooldown {
			want = 1 // second request goes to cpu first
		}
		if peer.n() != want {
			t.Errorf("peer status %d: peer hit %d times, want %d", tc.status, peer.n(), want)
		}
	}
}
