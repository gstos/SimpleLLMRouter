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

const (
	notesKey = "sr-notes-key"  // providers: [laya]
	adminKey = "sr-admin-key"  // providers: ["*"]
	plainKey = "sr-models-key" // no providers
)

func managedSetup(t *testing.T) (*Server, *config.Config, map[string]*anthUpstream) {
	t.Helper()
	mk, _ := secrets.GenerateKey()
	ci, _ := secrets.New(mk)
	ups := map[string]*anthUpstream{}
	for _, n := range []string{"laya", "llama", "oc"} {
		ups[n] = newAnthUpstream(t, n, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	}
	enc, _ := ci.Encrypt("laya-secret")
	cfg := &config.Config{
		Providers: []config.Provider{
			{Name: "laya", BaseURL: ups["laya"].srv.URL, APIKey: enc, AllowPaths: []string{"/v1/*", "/health"}},
			{Name: "llama", BaseURL: ups["llama"].srv.URL},
			{Name: "oc", BaseURL: ups["oc"].srv.URL, Auth: config.AuthPassthrough},
		},
		APIKeys: []config.APIKey{
			{Name: "notes", Hash: auth.Hash(notesKey), Providers: []string{"laya"}},
			{Name: "admin", Hash: auth.Hash(adminKey), Providers: []string{"*"}},
			{Name: "models-only", Hash: auth.Hash(plainKey)},
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
	return srv, cfg, ups
}

func managedDo(h http.Handler, method, target string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(`{"x":1}`))
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func reqCount(u *anthUpstream) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}

func TestManagedRequiresRouterKey(t *testing.T) {
	srv, _, ups := managedSetup(t)
	h := srv.Handler()
	for _, c := range []struct {
		hdr  []string
		code int
	}{
		{nil, 401},
		{[]string{"Authorization", "Bearer wrong"}, 401},
		{[]string{"Authorization", "Bearer " + plainKey}, 404}, // valid key, not granted: like unknown
		{[]string{"Authorization", "Bearer " + notesKey}, 200},
		{[]string{"X-Api-Key", notesKey}, 200},
	} {
		if w := managedDo(h, "POST", "/provider/laya/v1/classify", c.hdr...); w.Code != c.code {
			t.Errorf("%v: %d, want %d (%s)", c.hdr, w.Code, c.code, w.Body.String())
		}
	}
	// A granted key gets the same 404 for an unknown provider as for one it may not use.
	if a, b := managedDo(h, "GET", "/provider/nope/x", "Authorization", "Bearer "+notesKey), managedDo(h, "GET", "/provider/llama/x", "Authorization", "Bearer "+notesKey); a.Code != 404 || b.Code != 404 {
		t.Fatalf("unknown %d, not granted %d", a.Code, b.Code)
	}
	if n := reqCount(ups["llama"]); n != 0 {
		t.Fatalf("llama got %d requests", n)
	}
}

func TestManagedSwapsCredentials(t *testing.T) {
	srv, _, ups := managedSetup(t)
	h := srv.Handler()
	managedDo(h, "POST", "/provider/laya/v1/classify?x=1", "Authorization", "Bearer "+notesKey, "X-Api-Key", notesKey, "X-Custom", "kept")
	r := ups["laya"].last()
	if r.path != "/v1/classify" || r.query != "x=1" || r.body != `{"x":1}` {
		t.Fatalf("forwarded %+v", r)
	}
	if r.header.Get("Authorization") != "Bearer laya-secret" || r.header.Get("X-Api-Key") != "" || r.header.Get("X-Custom") != "kept" {
		t.Fatalf("headers: %v", r.header)
	}
	for k, vs := range r.header {
		for _, v := range vs {
			if strings.Contains(v, notesKey) {
				t.Fatalf("router key leaked upstream in %s", k)
			}
		}
	}
	// No stored key (llama-swap): the router key is stripped and nothing is sent.
	managedDo(h, "GET", "/provider/llama/upstream/m/health", "Authorization", "Bearer "+adminKey)
	if r := ups["llama"].last(); r.path != "/upstream/m/health" || r.header.Get("Authorization") != "" {
		t.Fatalf("llama got %+v", r)
	}
}

func TestAllowPaths(t *testing.T) {
	srv, _, ups := managedSetup(t)
	h := srv.Handler()
	for target, code := range map[string]int{
		"/provider/laya/v1/classify": 200,
		"/provider/laya/v1/":         200,
		"/provider/laya/health":      200,
		"/provider/laya/healthz":     403, // exact entry, not a prefix
		"/provider/laya/admin":       403,
		"/provider/laya/v2/x":        403,
	} {
		if w := managedDo(h, "GET", target, "Authorization", "Bearer "+notesKey); w.Code != code {
			t.Errorf("%s: %d, want %d", target, w.Code, code)
		}
	}
	// ".." is resolved before the check (handler called directly: no mux cleaning).
	r := httptest.NewRequest("GET", "/provider/laya/v1/x", nil)
	r.URL.Path = "/provider/laya/v1/../admin"
	r.Header.Set("Authorization", "Bearer "+notesKey)
	w := httptest.NewRecorder()
	srv.direct(w, r)
	if w.Code != 403 {
		t.Fatalf("../ escaped allow_paths: %d", w.Code)
	}
	if n := reqCount(ups["laya"]); n != 3 {
		t.Fatalf("laya got %d requests, want 3", n)
	}
}

func TestDirectWhileSealed(t *testing.T) {
	srv, cfg, ups := managedSetup(t)
	srv.Seal(cfg)
	h := srv.Handler()
	if w := managedDo(h, "GET", "/provider/laya/v1/x", "Authorization", "Bearer "+notesKey); w.Code != 503 {
		t.Fatalf("managed while sealed: %d", w.Code)
	}
	if w := managedDo(h, "GET", "/provider/laya/v1/x"); w.Code != 401 {
		t.Fatalf("no key while sealed: %d", w.Code)
	}
	if w := managedDo(h, "GET", "/provider/oc/models", "Authorization", "Bearer client-own"); w.Code != 200 || ups["oc"].last().header.Get("Authorization") != "Bearer client-own" {
		t.Fatalf("passthrough while sealed: %d", w.Code)
	}
}
