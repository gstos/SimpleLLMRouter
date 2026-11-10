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
)

const privateKey, openKey = "sr-private", "sr-open"

func okUpstream(t *testing.T, name string) *anthUpstream {
	return newAnthUpstream(t, name, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
}

func noExternalHandler(t *testing.T, provs []config.Provider, models []config.Model) http.Handler {
	t.Helper()
	cfg := &config.Config{
		Providers: provs,
		Models:    models,
		APIKeys: []config.APIKey{
			{Name: "private", Hash: auth.Hash(privateKey), Providers: []string{"*"}, DisableExternal: true},
			{Name: "open", Hash: auth.Hash(openKey), Providers: []string{"*"}},
		},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	srv := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	srv.Update(cfg, router.New(cfg, nil), health.New(cfg.Providers, time.Second, nil))
	return srv.Handler()
}

func keyPost(h http.Handler, key, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// External first, then a peer, then local: a key with disable_external skips the
// external provider (even when it is first and healthy), and may use peers.
func TestDisableExternalKeySkipsExternal(t *testing.T) {
	ext, peer, local := okUpstream(t, "ext"), okUpstream(t, "peer"), okUpstream(t, "local")
	peer.fail.Store(503)
	h := noExternalHandler(t,
		[]config.Provider{
			{Name: "or", BaseURL: ext.srv.URL + "/v1", External: true},
			{Name: "router-b", BaseURL: peer.srv.URL + "/v1", Peer: true},
			{Name: "cpu", BaseURL: local.srv.URL + "/v1"},
		},
		[]config.Model{
			{Name: "m", Targets: []config.Target{
				{Provider: "or", Priority: 1}, {Provider: "router-b", Priority: 2}, {Provider: "cpu", Priority: 3},
			}},
			{Name: "cloud", Targets: []config.Target{{Provider: "or"}}},
		},
	)
	w := keyPost(h, privateKey, "POST", "/v1/chat/completions", peerChatBody)
	if w.Code != 200 || w.Header().Get("X-Router-Provider") != "cpu" {
		t.Fatalf("private: %d via %q", w.Code, w.Header().Get("X-Router-Provider"))
	}
	if ext.n() != 0 || peer.n() != 1 {
		t.Fatalf("private key hits: external=%d peer=%d, want 0 and 1", ext.n(), peer.n())
	}
	// Only external targets: 503, nothing sent.
	if w := keyPost(h, privateKey, "POST", "/v1/chat/completions", `{"model":"cloud","messages":[]}`); w.Code != 503 || ext.n() != 0 {
		t.Fatalf("private on external-only model: %d, external hits %d", w.Code, ext.n())
	}
	// Other keys are unaffected.
	if w := keyPost(h, openKey, "POST", "/v1/chat/completions", peerChatBody); w.Code != 200 || ext.n() != 1 {
		t.Fatalf("open key: %d, external hits %d", w.Code, ext.n())
	}
}

func TestDisableExternalKeyDirectAccess(t *testing.T) {
	ext, local := okUpstream(t, "ext"), okUpstream(t, "local")
	h := noExternalHandler(t,
		[]config.Provider{
			{Name: "or", BaseURL: ext.srv.URL + "/v1", External: true},
			{Name: "cpu", BaseURL: local.srv.URL + "/v1"},
		},
		[]config.Model{{Name: "m", Targets: []config.Target{{Provider: "cpu"}}}},
	)
	if w := keyPost(h, privateKey, "GET", "/provider/or/models", ""); w.Code != 404 || ext.n() != 0 {
		t.Fatalf("private key reached external provider directly: %d", w.Code)
	}
	if w := keyPost(h, privateKey, "GET", "/provider/cpu/models", ""); w.Code != 200 {
		t.Fatalf("private key on local provider: %d", w.Code)
	}
	if w := keyPost(h, openKey, "GET", "/provider/or/models", ""); w.Code != 200 {
		t.Fatalf("open key on external provider: %d", w.Code)
	}
}

// Passthrough checks nothing, but a disable_external key presented in either
// header still never reaches an external provider; other credentials pass.
func TestDisableExternalKeyPassthroughTunnel(t *testing.T) {
	ext := okUpstream(t, "ext")
	h := noExternalHandler(t,
		[]config.Provider{{Name: "oc", BaseURL: ext.srv.URL + "/v1", Auth: config.AuthPassthrough, External: true}},
		[]config.Model{},
	)
	send := func(hdr ...string) int {
		r := httptest.NewRequest("POST", "/provider/oc/chat/completions", strings.NewReader(`{"x":1}`))
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for name, hdr := range map[string][]string{
		"authorization": {"Authorization", "Bearer " + privateKey, "X-Api-Key", "sk-provider"},
		"x-api-key":     {"Authorization", "Bearer sk-provider", "X-Api-Key", privateKey},
	} {
		if code := send(hdr...); code != 404 {
			t.Errorf("%s: private key through passthrough: %d", name, code)
		}
	}
	if ext.n() != 0 {
		t.Fatalf("external passthrough provider got %d requests", ext.n())
	}
	if code := send("Authorization", "Bearer sk-provider"); code != 200 || ext.n() != 1 {
		t.Fatalf("provider credential through passthrough: %d", code)
	}
	if code := send("Authorization", "Bearer "+openKey); code != 200 {
		t.Fatalf("other router key through passthrough: %d", code)
	}
}

func TestDisableExternalKeyModelList(t *testing.T) {
	ext, local := okUpstream(t, "ext"), okUpstream(t, "local")
	h := noExternalHandler(t,
		[]config.Provider{
			{Name: "or", BaseURL: ext.srv.URL + "/v1", External: true},
			{Name: "router-b", BaseURL: local.srv.URL + "/v1", Peer: true},
		},
		[]config.Model{
			{Name: "cloud", Aliases: []string{"cloud-alias"}, Targets: []config.Target{{Provider: "or"}}},
			{Name: "shared", Targets: []config.Target{{Provider: "or", Priority: 1}, {Provider: "router-b", Priority: 2}}},
		},
	)
	list := func(key string) string { return keyPost(h, key, "GET", "/v1/models", "").Body.String() }
	priv, open := list(privateKey), list(openKey)
	if strings.Contains(priv, `"cloud"`) || strings.Contains(priv, "cloud-alias") || !strings.Contains(priv, `"shared"`) {
		t.Errorf("private key list: %s", priv)
	}
	if !strings.Contains(open, `"cloud"`) || !strings.Contains(open, "cloud-alias") {
		t.Errorf("open key list: %s", open)
	}
	if ext.n()+local.n() != 0 {
		t.Fatal("listing models contacted a provider")
	}
}
