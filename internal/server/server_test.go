package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/health"
	"github.com/gstos/SimpleLLMRouter/internal/router"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

type fakeUpstream struct {
	name string
	srv  *httptest.Server
	mu   sync.Mutex
	fail int // status to return; 0 = OK
	hits int
	last map[string]any
	auth string
}

func newUpstream(t *testing.T, name string) *fakeUpstream {
	u := &fakeUpstream{name: name}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		defer u.mu.Unlock()
		if r.URL.Path == "/models" {
			return
		}
		u.hits++
		u.auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&u.last)
		if u.fail != 0 {
			w.WriteHeader(u.fail)
			_, _ = io.WriteString(w, `{"error":"boom"}`)
			return
		}
		if u.last["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"from\":\""+name+"\"}\n\ndata: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"from":"`+name+`","path":"`+r.URL.Path+`"}`)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *fakeUpstream) setFail(s int) { u.mu.Lock(); u.fail = s; u.mu.Unlock() }

const (
	fullKey    = "sr-full"
	limitedKey = "sr-limited"
)

func setup(t *testing.T) (http.Handler, map[string]*fakeUpstream) {
	ups := map[string]*fakeUpstream{}
	mk, _ := secrets.GenerateKey()
	ci, _ := secrets.New(mk)
	var provs []config.Provider
	for _, n := range []string{"a", "b", "c"} {
		ups[n] = newUpstream(t, n)
		enc, _ := ci.Encrypt("key-" + n)
		provs = append(provs, config.Provider{Name: n, BaseURL: ups[n].srv.URL, APIKey: enc})
	}
	cfg := &config.Config{
		Providers: provs,
		Models: []config.Model{
			{Name: "gpt", Targets: []config.Target{
				{Provider: "a", Model: "gpt-a", Priority: 1},
				{Provider: "b", Model: "gpt-b", Priority: 1},
				{Provider: "c", Model: "gpt-c", Priority: 2},
			}},
			{Name: "embed", Type: config.TypeEmbedding, Targets: []config.Target{{Provider: "c"}}},
			{Name: "rr", Type: config.TypeRerank, Targets: []config.Target{{Provider: "b"}}},
		},
		APIKeys: []config.APIKey{
			{Name: "full", Hash: auth.Hash(fullKey), Models: []string{"*"}, Admin: true},
			{Name: "limited", Hash: auth.Hash(limitedKey), Models: []string{"emb*"}},
		},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.DecryptSecrets(ci); err != nil {
		t.Fatal(err)
	}
	rt := router.New(cfg, nil)
	ch := health.New(cfg.Providers, time.Second, func(r health.Result) { rt.SetProviderHealthy(r.Provider, r.Healthy) })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(log, Options{})
	srv.Update(cfg, rt, ch)
	return srv.Handler(), ups
}

func do(t *testing.T, h http.Handler, key, path string, body map[string]any, hdr ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+key)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func chat(session string) map[string]any {
	return map[string]any{"model": "gpt", "messages": []any{map[string]any{"role": "user", "content": session}}}
}

func TestRoundRobinAcrossSessions(t *testing.T) {
	h, ups := setup(t)
	for i := 0; i < 10; i++ {
		rec, _ := do(t, h, fullKey, "/api/v1/chat/completions", chat(string(rune('a'+i))))
		if rec.Code != 200 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	}
	if ups["a"].hits != 5 || ups["b"].hits != 5 || ups["c"].hits != 0 {
		t.Fatalf("hits a=%d b=%d c=%d", ups["a"].hits, ups["b"].hits, ups["c"].hits)
	}
	if ups["a"].last["model"] != "gpt-a" || ups["a"].auth != "Bearer key-a" {
		t.Fatalf("upstream got model=%v auth=%q", ups["a"].last["model"], ups["a"].auth)
	}
}

func TestStickySession(t *testing.T) {
	h, _ := setup(t)
	first := ""
	for i := 0; i < 5; i++ {
		rec, out := do(t, h, fullKey, "/v1/chat/completions", chat("same conversation"))
		if rec.Code != 200 {
			t.Fatal(rec.Body)
		}
		if first == "" {
			first = out["from"].(string)
		} else if out["from"] != first {
			t.Fatalf("request %d went to %v, want sticky %s", i, out["from"], first)
		}
	}
}

func TestFailoverIsSticky(t *testing.T) {
	h, ups := setup(t)
	// Find which provider the session lands on, then break it.
	_, out := do(t, h, fullKey, "/api/v1/chat/completions", chat("s1"), "X-Session-Id", "s1")
	primary := out["from"].(string)
	other := map[string]string{"a": "b", "b": "a"}[primary]
	ups[primary].setFail(503)

	_, out = do(t, h, fullKey, "/api/v1/chat/completions", chat("s1"), "X-Session-Id", "s1")
	if out["from"] != other {
		t.Fatalf("failover went to %v, want %s", out["from"], other)
	}
	// Primary recovers, but the session stays on the failover target.
	ups[primary].setFail(0)
	for i := 0; i < 3; i++ {
		_, out = do(t, h, fullKey, "/api/v1/chat/completions", chat("s1"), "X-Session-Id", "s1")
		if out["from"] != other {
			t.Fatalf("after recovery went to %v, want sticky %s", out["from"], other)
		}
	}
}

func TestFallsThroughPriorities(t *testing.T) {
	h, ups := setup(t)
	ups["a"].setFail(500)
	ups["b"].setFail(429)
	rec, out := do(t, h, fullKey, "/api/v1/chat/completions", chat("x"))
	if rec.Code != 200 || out["from"] != "c" || rec.Header().Get("X-Router-Provider") != "c" {
		t.Fatalf("status=%d from=%v", rec.Code, out["from"])
	}

	ups["c"].setFail(502)
	rec, _ = do(t, h, fullKey, "/api/v1/chat/completions", chat("y"))
	if rec.Code < 400 {
		t.Fatalf("expected error when all fail, got %d", rec.Code)
	}
}

func TestClientErrorNotRetried(t *testing.T) {
	h, ups := setup(t)
	ups["a"].setFail(400)
	ups["b"].setFail(400)
	rec, _ := do(t, h, fullKey, "/api/v1/chat/completions", chat("z"))
	if rec.Code != 400 || ups["a"].hits+ups["b"].hits != 1 || ups["c"].hits != 0 {
		t.Fatalf("status=%d hits a=%d b=%d c=%d", rec.Code, ups["a"].hits, ups["b"].hits, ups["c"].hits)
	}
}

func TestKeyRestrictionsAndTypes(t *testing.T) {
	h, _ := setup(t)
	if rec, _ := do(t, h, "nope", "/api/v1/chat/completions", chat("q")); rec.Code != 401 {
		t.Fatalf("bad key: %d", rec.Code)
	}
	if rec, _ := do(t, h, limitedKey, "/api/v1/chat/completions", chat("q")); rec.Code != 404 {
		t.Fatalf("limited key on gpt: %d", rec.Code)
	}
	rec, out := do(t, h, limitedKey, "/api/v1/embeddings", map[string]any{"model": "embed", "input": "hi"})
	if rec.Code != 200 || out["path"] != "/embeddings" {
		t.Fatalf("embeddings: %d %v", rec.Code, out)
	}
	if rec, _ := do(t, h, fullKey, "/api/v1/embeddings", chat("q")); rec.Code != 400 {
		t.Fatalf("chat model on embeddings: %d", rec.Code)
	}
	rec, out = do(t, h, fullKey, "/api/v1/rerank", map[string]any{"model": "rr", "query": "q", "documents": []string{"a"}})
	if rec.Code != 200 || out["path"] != "/rerank" {
		t.Fatalf("rerank: %d %v", rec.Code, out)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+limitedKey)
	mr := httptest.NewRecorder()
	h.ServeHTTP(mr, req)
	if !strings.Contains(mr.Body.String(), `"embed"`) || strings.Contains(mr.Body.String(), `"gpt"`) {
		t.Fatalf("models for limited key: %s", mr.Body)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	req.Header.Set("Authorization", "Bearer "+limitedKey)
	ar := httptest.NewRecorder()
	h.ServeHTTP(ar, req)
	if ar.Code != 403 {
		t.Fatalf("admin health with non-admin key: %d", ar.Code)
	}
}

func TestStreaming(t *testing.T) {
	h, _ := setup(t)
	body := chat("stream")
	body["stream"] = true
	rec, _ := do(t, h, fullKey, "/api/v1/chat/completions", body)
	if rec.Header().Get("Content-Type") != "text/event-stream" || !strings.Contains(rec.Body.String(), "[DONE]") {
		t.Fatalf("stream: %q %q", rec.Header().Get("Content-Type"), rec.Body)
	}
}

func TestAdminHealth(t *testing.T) {
	h, ups := setup(t)
	ups["b"].srv.Close()
	req := httptest.NewRequest(http.MethodGet, "/admin/health?refresh=1", nil)
	req.Header.Set("Authorization", "Bearer "+fullKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), `"provider":"b","healthy":false`) {
		t.Fatalf("health: %d %s", rec.Code, rec.Body)
	}
	// b is now known-down, so traffic avoids it without paying for a failed attempt.
	for i := 0; i < 4; i++ {
		_, out := do(t, h, fullKey, "/api/v1/chat/completions", chat(string(rune('k'+i))))
		if out["from"] != "a" {
			t.Fatalf("routed to %v while b is down", out["from"])
		}
	}
}

func TestSealedAndUnseal(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{{Name: "a", BaseURL: "http://a"}},
		Models:    []config.Model{{Name: "gpt", Targets: []config.Target{{Provider: "a"}}}},
		APIKeys: []config.APIKey{
			{Name: "full", Hash: auth.Hash(fullKey), Admin: true},
			{Name: "limited", Hash: auth.Hash(limitedKey)},
		},
	}
	cfg.ApplyDefaults()

	var got string
	srv := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{
		Unseal: func(_ context.Context, key string) error {
			if key != "right" {
				return fmt.Errorf("%w: nope", ErrKeyRejected)
			}
			got = key
			return nil
		},
	})
	srv.Seal(cfg)
	handler := srv.Handler()

	if rec, _ := do(t, handler, fullKey, "/api/v1/chat/completions", chat("x")); rec.Code != 503 {
		t.Fatalf("sealed chat: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "sealed\n" {
		t.Fatalf("healthz while sealed: %d %q", rec.Code, rec.Body)
	}

	unseal := func(key, mk, remote string) int {
		b, _ := json.Marshal(map[string]string{"master_key": mk})
		req := httptest.NewRequest(http.MethodPost, "/admin/unseal", bytes.NewReader(b))
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := unseal(fullKey, "right", "203.0.113.5:4000"); c != 403 {
		t.Fatalf("remote unseal: %d", c)
	}
	if c := unseal(limitedKey, "right", "127.0.0.1:4000"); c != 403 {
		t.Fatalf("non-admin unseal: %d", c)
	}
	if c := unseal("bogus", "right", "127.0.0.1:4000"); c != 401 {
		t.Fatalf("bad client key: %d", c)
	}
	if c := unseal(fullKey, "wrong", "[::1]:4000"); c != 422 {
		t.Fatalf("wrong master key: %d", c)
	}
	if c := unseal(fullKey, "right", "127.0.0.1:4000"); c != 200 || got != "right" {
		t.Fatalf("unseal: %d", c)
	}
}

func TestRotateEndpoint(t *testing.T) {
	cfg := &config.Config{APIKeys: []config.APIKey{{Name: "full", Hash: auth.Hash(fullKey), Admin: true}}}
	cfg.ApplyDefaults()
	srv := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{
		Rotate: func(_ context.Context, cur, newKey string) (string, error) {
			if cur != "current" {
				return "", fmt.Errorf("%w: nope", ErrKeyRejected)
			}
			if newKey == "" {
				newKey = "generated"
			}
			return newKey, nil
		},
	})
	srv.Seal(cfg)
	h := srv.Handler()
	call := func(body map[string]string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/admin/rotate-master-key", bytes.NewReader(b))
		req.RemoteAddr = "127.0.0.1:1"
		req.Header.Set("Authorization", "Bearer "+fullKey)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := call(map[string]string{"master_key": "current"}); rec.Code != 503 {
		t.Fatalf("rotate while sealed: %d", rec.Code)
	}
	srv.Update(cfg, router.New(cfg, nil), health.New(nil, time.Second, nil))
	if rec := call(map[string]string{"new_master_key": "x"}); rec.Code != 400 {
		t.Fatalf("missing current key: %d", rec.Code)
	}
	if rec := call(map[string]string{"master_key": "wrong"}); rec.Code != 422 {
		t.Fatalf("wrong current key: %d", rec.Code)
	}
	rec := call(map[string]string{"master_key": "current"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"master_key":"generated"`) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("rotate: %d %s %q", rec.Code, rec.Body, rec.Header().Get("Cache-Control"))
	}
	if rec := call(map[string]string{"master_key": "current", "new_master_key": "mine"}); !strings.Contains(rec.Body.String(), `"master_key":"mine"`) {
		t.Fatalf("caller-supplied key: %s", rec.Body)
	}
}
