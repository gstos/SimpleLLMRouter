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

const aliasKey, scopedKey = "sr-alias-full", "sr-alias-scoped"

func aliasSetup(t *testing.T) (http.Handler, map[string]*anthUpstream) {
	t.Helper()
	mk, _ := secrets.GenerateKey()
	ci, _ := secrets.New(mk)
	ups := map[string]*anthUpstream{}
	var provs []config.Provider
	for _, n := range []string{"a", "b"} {
		ups[n] = newAnthUpstream(t, n, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":[]}`)
		})
		enc, _ := ci.Encrypt("k-" + n)
		provs = append(provs, config.Provider{Name: n, BaseURL: ups[n].srv.URL + "/v1", APIKey: enc})
	}
	cfg := &config.Config{
		Providers: provs,
		Models: []config.Model{
			{Name: "bge-m3", Aliases: []string{"baai/bge-m3"}, Type: config.TypeEmbedding, Targets: []config.Target{
				{Provider: "a", Model: "bge-m3", Priority: 1}, {Provider: "b", Model: "bge-m3", Priority: 1},
			}},
			{Name: "other", Targets: []config.Target{{Provider: "a", Model: "x"}}},
		},
		APIKeys: []config.APIKey{
			{Name: "full", Hash: auth.Hash(aliasKey)},
			{Name: "scoped", Hash: auth.Hash(scopedKey), Models: []string{"bge-*"}}, // matches the name only
		},
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
	return srv.Handler(), ups
}

func aliasPost(h http.Handler, key, model string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/embeddings", strings.NewReader(`{"model":"`+model+`","input":"x"}`))
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("X-Session-Id", "s1") // sticky: same conversation for both names
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAliasRoutesLikeModel(t *testing.T) {
	h, ups := aliasSetup(t)
	w := aliasPost(h, aliasKey, "bge-m3")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	first := w.Header().Get("X-Router-Provider")
	for i := 0; i < 4; i++ {
		w := aliasPost(h, aliasKey, "baai/bge-m3")
		if w.Code != 200 || w.Header().Get("X-Router-Provider") != first {
			t.Fatalf("alias left the sticky provider %s: %d %v", first, w.Code, w.Header())
		}
	}
	if b := ups[first].last().body; !strings.Contains(b, `"model":"bge-m3"`) {
		t.Fatalf("upstream model not rewritten: %s", b)
	}
	// A key scoped to the model name may use its alias too.
	if w := aliasPost(h, scopedKey, "baai/bge-m3"); w.Code != 200 {
		t.Fatalf("scoped key denied the alias: %d", w.Code)
	}
	if w := aliasPost(h, scopedKey, "other"); w.Code != 404 {
		t.Fatalf("scoped key reached another model: %d", w.Code)
	}
	if w := aliasPost(h, aliasKey, "baai/unknown"); w.Code != 404 {
		t.Fatalf("unknown alias: %d", w.Code)
	}
}

func TestAliasListedInModels(t *testing.T) {
	h, _ := aliasSetup(t)
	list := func(key string) string {
		r := httptest.NewRequest("GET", "/v1/models", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Body.String()
	}
	if b := list(aliasKey); !strings.Contains(b, `"id":"bge-m3"`) || !strings.Contains(b, `"id":"baai/bge-m3"`) || !strings.Contains(b, `"id":"other"`) {
		t.Fatalf("full key list: %s", b)
	}
	if b := list(scopedKey); !strings.Contains(b, `"id":"baai/bge-m3"`) || strings.Contains(b, `"id":"other"`) {
		t.Fatalf("scoped key list: %s", b)
	}
}

func TestAliasDoesNotWidenAccess(t *testing.T) {
	up := newAnthUpstream(t, "a", nil)
	cfg := &config.Config{
		Providers: []config.Provider{{Name: "a", BaseURL: up.srv.URL + "/v1"}},
		Models: []config.Model{
			// An alias in the namespace a scoped key may use.
			{Name: "private-model", Aliases: []string{"bge-private"}, Type: config.TypeEmbedding,
				Targets: []config.Target{{Provider: "a", Model: "m"}}},
		},
		APIKeys: []config.APIKey{{Name: "scoped", Hash: auth.Hash(scopedKey), Models: []string{"bge-*"}}},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	srv := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	srv.Update(cfg, router.New(cfg, nil), health.New(cfg.Providers, time.Second, nil))
	h := srv.Handler()
	if w := aliasPost(h, scopedKey, "bge-private"); w.Code != 404 {
		t.Fatalf("alias granted a model the key may not use: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "/v1/models", nil)
	r.Header.Set("Authorization", "Bearer "+scopedKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "bge-private") {
		t.Fatalf("alias listed for a key without access: %s", w.Body.String())
	}
}
