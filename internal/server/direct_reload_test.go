package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"

	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/router"
)

type snapshotTestTransport struct{}

func (snapshotTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}, nil
}

func TestDirectUsesSingleSnapshotDuringProviderRemoval(t *testing.T) {
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	s.client.Transport = snapshotTestTransport{}
	keys := auth.NewStore([]config.APIKey{{Name: "admin", Hash: auth.Hash("router-key"), Providers: []string{"*"}}})
	cfg := &config.Config{Providers: []config.Provider{{Name: "p", BaseURL: "https://provider.test"}}}
	cfg.ApplyDefaults()
	present := &snapshot{cfg: cfg, keys: keys, router: router.New(cfg, nil)}
	missingCfg := &config.Config{}
	missingCfg.ApplyDefaults()
	missing := &snapshot{cfg: missingCfg, keys: keys, router: router.New(missingCfg, nil)}
	s.cur.Store(present)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				s.cur.Store(present)
				runtime.Gosched()
				s.cur.Store(missing)
				runtime.Gosched()
			}
		}
	}()
	defer func() { close(done); wg.Wait() }()
	for i := 0; i < 10000; i++ {
		r := httptest.NewRequest("GET", "/provider/p/models", nil)
		r.Header.Set("Authorization", "Bearer router-key")
		w := httptest.NewRecorder()
		s.direct(w, r)
		if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 200 or 404", w.Code)
		}
	}
}

func TestSnapshotAuthenticationSurvivesKeyReload(t *testing.T) {
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	s.Seal(&config.Config{APIKeys: []config.APIKey{{Name: "old", Hash: auth.Hash("old-key")}}})
	old := s.cur.Load()
	s.Seal(&config.Config{APIKeys: []config.APIKey{{Name: "new", Hash: auth.Hash("new-key")}}})
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer old-key")
	if key := old.authenticate(httptest.NewRecorder(), r); key == nil || key.Name != "old" {
		t.Fatal("in-flight snapshot did not retain its authentication rules")
	}
	if _, key := s.authenticate(httptest.NewRecorder(), r); key != nil {
		t.Fatal("new requests still accept the removed key")
	}
}
