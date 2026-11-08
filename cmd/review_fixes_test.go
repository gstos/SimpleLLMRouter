package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/config"
)

func TestHTTPSRedirectIPv6(t *testing.T) {
	for _, c := range []struct{ listen, host, want string }{
		{":443", "[2001:db8::1]", "https://[2001:db8::1]/x"},
		{":443", "[2001:db8::1]:80", "https://[2001:db8::1]/x"},
		{":8443", "[2001:db8::1]", "https://[2001:db8::1]:8443/x"},
		{":8443", "router.lan", "https://router.lan:8443/x"},
		{":443", "10.0.0.5:80", "https://10.0.0.5/x"},
	} {
		r := httptest.NewRequest("GET", "/x", nil)
		r.Host = c.host
		w := httptest.NewRecorder()
		httpsRedirect(c.listen).ServeHTTP(w, r)
		if got := w.Header().Get("Location"); got != c.want {
			t.Errorf("listen %s host %s: %q, want %q", c.listen, c.host, got, c.want)
		}
	}
}

func TestTLSChangedIgnoresDNSEnv(t *testing.T) {
	a := config.TLS{Mode: config.TLSACME, ACME: config.ACME{Email: "a@b.c", DNSEnv: map[string]string{"TOKEN": "enc:v1:x"}}}
	b := a
	b.ACME.DNSEnv = map[string]string{"TOKEN": "decrypted"}
	if tlsChanged(a, b) {
		t.Fatal("decrypted dns_env reported as a TLS change")
	}
	b.ACME.Email = "other@b.c"
	if !tlsChanged(a, b) {
		t.Fatal("real change missed")
	}
}

func TestCertNameSkipsInvalidCertificates(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, from, to time.Time) string {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "router.test"},
			DNSNames: []string{"router.test"}, NotBefore: from, NotAfter: to}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	now := time.Now()
	if n := certName(write("valid", now.Add(-time.Hour), now.Add(time.Hour))); n != "router.test" {
		t.Fatalf("valid: %q", n)
	}
	if n := certName(write("expired", now.Add(-48*time.Hour), now.Add(-time.Hour))); n != "" {
		t.Fatalf("expired certificate used as ServerName: %q", n)
	}
	if n := certName(write("future", now.Add(time.Hour), now.Add(48*time.Hour))); n != "" {
		t.Fatalf("not-yet-valid certificate used as ServerName: %q", n)
	}
}
