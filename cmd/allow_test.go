package cmd

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gstos/SimpleLLMRouter/internal/allowlist"
)

// The plain-HTTP listener with ACME HTTP-01 must serve challenge files to any
// peer but refuse everything else from a disallowed one.
func TestRedirectGuardACMEExemption(t *testing.T) {
	webroot := t.TempDir()
	dir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tok"), []byte("keyauth"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := allowlist.NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	l, err := allowlist.Parse([]string{"192.168.0.0/16"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	g.Set(l)

	get := func(h http.Handler, remote, path string) int {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	acme := redirectGuard(g, acmeChallenges(webroot, httpsRedirect(":443")), true)
	if c := get(acme, "8.8.8.8:1", "/.well-known/acme-challenge/tok"); c != 200 {
		t.Errorf("challenge from outside: %d", c)
	}
	if c := get(acme, "8.8.8.8:1", "/anything"); c != 403 {
		t.Errorf("redirect for disallowed peer: %d", c)
	}
	if c := get(acme, "192.168.1.1:1", "/anything"); c != 308 {
		t.Errorf("allowed peer redirect: %d", c)
	}
	// Without ACME HTTP-01 there is no exemption.
	plain := redirectGuard(g, httpsRedirect(":443"), false)
	if c := get(plain, "8.8.8.8:1", "/.well-known/acme-challenge/tok"); c != 403 {
		t.Errorf("no-exemption: %d", c)
	}
}
