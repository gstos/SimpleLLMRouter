package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/router"
)

func TestUpstreamRedirectsDoNotForwardCredentials(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var hits atomic.Int32
			dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
			}))
			defer dest.Close()
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Api-Key") != "provider-secret" {
					t.Error("initial request missing provider credential")
				}
				http.Redirect(w, r, dest.URL, status)
			}))
			defer source.Close()
			s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
			target := &router.Target{Provider: &config.Provider{
				BaseURL: source.URL, AuthHeader: "api-key", AuthScheme: "none", APIKey: "provider-secret",
			}}
			_, err := s.send(context.Background(), httptest.NewRequest("POST", "/", nil), target, config.EndpointChat, []byte(`{}`))
			if err == nil {
				t.Fatal("redirect was not rejected")
			}
			if hits.Load() != 0 {
				t.Fatal("redirect destination received a request")
			}
		})
	}
}
