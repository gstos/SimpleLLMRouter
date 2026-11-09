package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/config"
)

func TestHealthRedirectDoesNotForwardCredentials(t *testing.T) {
	var hits atomic.Int32
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer dest.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	p := config.Provider{BaseURL: source.URL, HealthMethod: "GET", APIKey: "secret", AuthHeader: "api-key", AuthScheme: "none"}
	c := New([]config.Provider{p}, time.Second, nil)
	res := c.Check(context.Background(), &p)
	if res.Healthy || res.Error == "" {
		t.Fatal("redirected health check was not rejected")
	}
	if hits.Load() != 0 {
		t.Fatal("redirect destination received a request")
	}
}

func TestHealthSendsRandomSession(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-Opencode-Session"))
	}))
	defer srv.Close()
	p := config.Provider{BaseURL: srv.URL, HealthMethod: "GET", AuthHeader: "Authorization", AuthScheme: "Bearer", SessionHeader: "X-Opencode-Session"}
	c := New([]config.Provider{p}, time.Second, nil)
	c.Check(context.Background(), &p)
	c.Check(context.Background(), &p)
	if len(seen) != 2 || len(seen[0]) != 32 || seen[0] == seen[1] {
		t.Fatalf("probe sessions: %q", seen)
	}
}

func TestHealthUsesHealthBaseURL(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { path = r.URL.Path }))
	defer srv.Close()
	p := config.Provider{BaseURL: srv.URL + "/zen/v1", BaseURLs: map[string]string{"health": srv.URL + "/inference/v1"}, HealthMethod: "GET", AuthHeader: "Authorization", AuthScheme: "Bearer"}
	c := New([]config.Provider{p}, time.Second, nil)
	if res := c.Check(context.Background(), &p); !res.Healthy {
		t.Fatalf("probe: %+v", res)
	}
	if path != "/inference/v1/models" {
		t.Fatalf("probe path %q", path)
	}
}
