package server

import (
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

// One provider, two prefixes: chat under base_url, embeddings under base_urls.
func TestBaseURLsPerEndpoint(t *testing.T) {
	up := newAnthUpstream(t, "p", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	mk, _ := secrets.GenerateKey()
	ci, _ := secrets.New(mk)
	enc, _ := ci.Encrypt("k-p")
	cfg := &config.Config{
		Providers: []config.Provider{{
			Name: "p", BaseURL: up.srv.URL + "/zen/go/v1", APIKey: enc,
			BaseURLs: map[string]string{"embeddings": up.srv.URL + "/inference/v1"},
		}},
		Models: []config.Model{
			{Name: "chat", Targets: []config.Target{{Provider: "p", Model: "c"}}},
			{Name: "emb", Type: config.TypeEmbedding, Targets: []config.Target{{Provider: "p", Model: "e"}}},
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
	h := srv.Handler()

	for _, c := range []struct{ path, model, want string }{
		{"/v1/chat/completions", "chat", "/zen/go/v1/chat/completions"},
		{"/v1/embeddings", "emb", "/inference/v1/embeddings"},
	} {
		r := httptest.NewRequest("POST", c.path, strings.NewReader(`{"model":"`+c.model+`","input":"x","messages":[{"role":"user","content":"hi"}]}`))
		r.Header.Set("Authorization", "Bearer sr-k")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", c.path, w.Code, w.Body.String())
		}
		up.mu.Lock()
		last := up.reqs[len(up.reqs)-1]
		up.mu.Unlock()
		if last.path != c.want || last.header.Get("Authorization") != "Bearer k-p" {
			t.Fatalf("%s: upstream got %s auth=%q", c.path, last.path, last.header.Get("Authorization"))
		}
	}
}
