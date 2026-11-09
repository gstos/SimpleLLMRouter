package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/health"
	"github.com/gstos/SimpleLLMRouter/internal/router"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

const s1Body = `{"model":"jev","state":"payments failed","questions":{"is_urgent":{"type":"noul","instructions":"urgent?"}}}`

// One opencode-go-like provider: chat under /zen/go/v1, System One under
// /inference/systemone/v1. Free target first, paid fallback.
func s1Setup(t *testing.T) (http.Handler, *anthUpstream) {
	t.Helper()
	up := newAnthUpstream(t, "oc", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"answers":{"is_urgent":{"type":"noul","noul":0.96}},"usage":{"cost":0}}`)
	})
	mk, _ := secrets.GenerateKey()
	ci, _ := secrets.New(mk)
	enc, _ := ci.Encrypt("k-oc")
	cfg := &config.Config{
		Providers: []config.Provider{{
			Name: "oc", BaseURL: up.srv.URL + "/zen/go/v1", APIKey: enc,
			BaseURLs: map[string]string{"systemone": up.srv.URL + "/inference/systemone/v1"},
		}},
		Models: []config.Model{
			{Name: "jev", Type: config.TypeSystemOne, Targets: []config.Target{
				{Provider: "oc", Model: "jev-1.13-free", Priority: 1},
				{Provider: "oc", Model: "jev-1.13", Priority: 2},
			}},
			{Name: "chat", Targets: []config.Target{{Provider: "oc", Model: "c"}}},
		},
		APIKeys: []config.APIKey{{Name: "k", Hash: auth.Hash("sr-k")}},
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
	return srv.Handler(), up
}

func s1Post(h http.Handler, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer sr-k")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSystemOneRoutes(t *testing.T) {
	h, up := s1Setup(t)
	for _, path := range []string{"/v1/systemone", "/api/v1/systemone"} {
		w := s1Post(h, path, s1Body)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"noul":0.96`) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if m := w.Header().Get("X-Router-Upstream-Model"); m != "jev-1.13-free" {
			t.Fatalf("%s: upstream model %q", path, m)
		}
	}
	got := up.last()
	if got.path != "/inference/systemone/v1/systemone" || got.header.Get("Authorization") != "Bearer k-oc" {
		t.Fatalf("upstream got %s auth=%q", got.path, got.header.Get("Authorization"))
	}
	if got.header.Get("Anthropic-Version") != "" {
		t.Fatal("systemone request got Anthropic-Version")
	}
	var b map[string]json.RawMessage
	if err := json.Unmarshal([]byte(got.body), &b); err != nil || string(b["model"]) != `"jev-1.13-free"` || len(b["questions"]) == 0 || len(b["state"]) == 0 {
		t.Fatalf("forwarded body %s", got.body)
	}
}

func TestSystemOneFailsOverToPaid(t *testing.T) {
	h, up := s1Setup(t)
	up.fail.Store(429)
	w := s1Post(h, "/v1/systemone", s1Body)
	// Both targets share the upstream, so both get 429: free is tried, then paid.
	up.mu.Lock()
	var models []string
	for _, r := range up.reqs {
		var b struct{ Model string }
		_ = json.Unmarshal([]byte(r.body), &b)
		models = append(models, b.Model)
	}
	up.mu.Unlock()
	if w.Code != 429 || strings.Join(models, ",") != "jev-1.13-free,jev-1.13" {
		t.Fatalf("status %d, tried %v", w.Code, models)
	}
}

func TestSystemOneTypeIsolation(t *testing.T) {
	h, _ := s1Setup(t)
	if w := s1Post(h, "/v1/chat/completions", s1Body); w.Code != 400 {
		t.Fatalf("systemone model on chat: %d", w.Code)
	}
	if w := s1Post(h, "/v1/systemone", `{"model":"chat","state":"x"}`); w.Code != 400 {
		t.Fatalf("chat model on systemone: %d", w.Code)
	}
}

func TestSystemOneStickyOnState(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/systemone", nil)
	key := func(state string) string {
		k, conv := stickyKey("k", "jev", r, map[string]json.RawMessage{"state": json.RawMessage(state)})
		if !conv {
			t.Fatal("state not used as session")
		}
		return k
	}
	if key(`"a"`) != key(`"a"`) || key(`"a"`) == key(`"b"`) {
		t.Fatal("sticky key not derived from state")
	}
}

func TestSystemOneStickyUsesEntireState(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/systemone", nil)
	key := func(suffix string) string {
		raw, err := json.Marshal(strings.Repeat("shared context ", 200) + suffix)
		if err != nil {
			t.Fatal(err)
		}
		k, _ := stickyKey("k", "jev", r, map[string]json.RawMessage{"state": raw})
		return k
	}
	if key("request one") == key("request two") {
		t.Fatal("distinct states with the same first 2048 bytes share a sticky key")
	}
	if key("request one") != key("request one") {
		t.Fatal("identical states have different sticky keys")
	}
}
