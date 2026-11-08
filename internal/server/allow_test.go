package server

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/config"
)

func TestAllowCIDRsAndReload(t *testing.T) {
	cfg := func(allow, trusted []string) *config.Config {
		c := &config.Config{APIKeys: []config.APIKey{{Name: "full", Hash: auth.Hash(fullKey), Models: []string{"*"}, Admin: true}}}
		c.Server.AllowCIDRs, c.Server.TrustedProxies = allow, trusted
		c.ApplyDefaults()
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	srv := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	srv.Seal(cfg([]string{"192.168.0.0/16"}, nil))
	h := srv.Handler()
	get := func(remote, path, xff string) (int, string) {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	for _, p := range []string{"/healthz", "/v1/models", "/provider/x/y", "/admin/health"} {
		code, body := get("8.8.8.8:1", p, "")
		if code != 403 || !strings.Contains(body, `"code":403`) {
			t.Errorf("%s from outside: %d %s", p, code, body)
		}
	}
	if code, _ := get("127.0.0.1:1", "/healthz", ""); code != 200 {
		t.Errorf("loopback healthz: %d", code)
	}
	if code, _ := get("192.168.1.1:1", "/healthz", ""); code != 200 {
		t.Errorf("allowed healthz: %d", code)
	}
	// Reload: trust the proxy 10.0.0.1, widen the allowlist.
	if code, _ := get("10.0.0.1:1", "/healthz", "192.168.1.1"); code != 403 {
		t.Errorf("untrusted proxy before reload: %d", code)
	}
	srv.Seal(cfg([]string{"192.168.0.0/16", "172.16.0.0/12"}, []string{"10.0.0.1"}))
	if code, _ := get("10.0.0.1:1", "/healthz", "192.168.1.1"); code != 200 {
		t.Errorf("trusted proxy after reload: %d", code)
	}
	if code, _ := get("172.16.0.9:1", "/healthz", ""); code != 200 {
		t.Errorf("new cidr after reload: %d", code)
	}
	srv.Update(cfg(nil, nil), nil, nil)
	if code, _ := get("8.8.8.8:1", "/healthz", ""); code != 200 {
		t.Errorf("empty list after reload: %d", code)
	}
}
