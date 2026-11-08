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
