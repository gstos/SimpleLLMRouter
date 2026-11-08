package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/config"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// writePair writes a self-signed certificate for name, valid in [from, to].
func writePair(t *testing.T, certPath, keyPath, name string, from, to time.Time) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    from,
		NotAfter:     to,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	must(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	must(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600))
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func fileCfg(dir string, fallback bool) config.TLS {
	return config.TLS{Mode: config.TLSFile, CertFile: "tls.crt", KeyFile: "tls.key", FallbackSelfSigned: &fallback, MinVersion: "1.2"}
}

func TestFileRotation(t *testing.T) {
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	now := time.Now()
	fp1 := writePair(t, crt, key, "one.test", now.Add(-time.Hour), now.Add(90*24*time.Hour))

	m, err := New(fileCfg(dir, false), dir, quiet)
	must(t, err)
	if i := m.Info(); i.Source != "file" || i.FingerprintSHA256 != fp1 {
		t.Fatalf("initial: %+v", i)
	}

	// Rotate: new pair is picked up.
	fp2 := writePair(t, crt, key, "two.test", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	changed, err := m.Reload()
	if err != nil || !changed || m.Info().FingerprintSHA256 != fp2 {
		t.Fatalf("rotate: changed=%v err=%v info=%+v", changed, err, m.Info())
	}

	// Mismatched key (cert from one pair, key from another): rejected, old kept.
	other := t.TempDir()
	writePair(t, filepath.Join(other, "c"), filepath.Join(other, "k"), "x.test", now.Add(-time.Hour), now.Add(time.Hour))
	b, _ := os.ReadFile(filepath.Join(other, "k"))
	must(t, os.WriteFile(key, b, 0o600))
	if _, err := m.Reload(); err == nil || m.Info().FingerprintSHA256 != fp2 {
		t.Fatalf("mismatch accepted: err=%v", err)
	}

	// Expired pair: rejected, old kept.
	writePair(t, crt, key, "old.test", now.Add(-48*time.Hour), now.Add(-time.Hour))
	if _, err := m.Reload(); err == nil || m.Info().FingerprintSHA256 != fp2 {
		t.Fatalf("expired accepted: err=%v", err)
	}

	// Garbage: rejected, old kept.
	must(t, os.WriteFile(crt, []byte("not a cert"), 0o644))
	if _, err := m.Reload(); err == nil || m.Info().FingerprintSHA256 != fp2 {
		t.Fatalf("garbage accepted: err=%v", err)
	}
}

func TestFallbackUntilFilesAppear(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(fileCfg(dir, false), dir, quiet); err == nil {
		t.Fatal("missing files accepted without fallback")
	}

	m, err := New(fileCfg(dir, true), dir, quiet)
	must(t, err)
	if m.Info().Source != "fallback" || !fileExists(m.SelfSignedCertPath()) {
		t.Fatalf("fallback not served: %+v", m.Info())
	}
	now := time.Now()
	fp := writePair(t, filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), "real.test", now.Add(-time.Hour), now.Add(time.Hour*24*60))
	if changed, err := m.Reload(); err != nil || !changed || m.Info().Source != "file" || m.Info().FingerprintSHA256 != fp {
		t.Fatalf("real cert not swapped in: %v %v %+v", changed, err, m.Info())
	}
}

func TestSelfSignedPersistedAndRegenerated(t *testing.T) {
	dir := t.TempDir()
	cfg := config.TLS{Mode: config.TLSSelfSigned, Domains: []string{"router.lan"}, MinVersion: "1.2"}
	m1, err := New(cfg, dir, quiet)
	must(t, err)
	fp := m1.Info().FingerprintSHA256

	// Restart: same certificate (clients keep trusting it).
	m2, err := New(cfg, dir, quiet)
	must(t, err)
	if m2.Info().FingerprintSHA256 != fp {
		t.Fatal("self-signed certificate not reused")
	}
	if st, _ := os.Stat(filepath.Join(dir, "tls", SelfSignedKey)); st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode().Perm())
	}

	// Names change: regenerated.
	cfg.Domains = []string{"other.lan"}
	m3, err := New(cfg, dir, quiet)
	must(t, err)
	if m3.Info().FingerprintSHA256 == fp {
		t.Fatal("not regenerated for new names")
	}

	// Close to expiry: regenerated on Reload.
	m3.now = func() time.Time { return time.Now().Add(340 * 24 * time.Hour) }
	if changed, err := m3.Reload(); err != nil || !changed {
		t.Fatalf("not renewed near expiry: %v %v", changed, err)
	}
}

// TestHandshakeSeesRotation serves TLS and checks that new connections get the
// rotated certificate with no restart, and that a client trusting the
// self-signed certificate verifies it.
func TestHandshakeSeesRotation(t *testing.T) {
	dir := t.TempDir()
	m, err := New(config.TLS{Mode: config.TLSSelfSigned, MinVersion: "1.2"}, dir, quiet)
	must(t, err)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", m.TLSConfig())
	must(t, err)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })}
	go srv.Serve(ln)
	defer srv.Close()

	pem, _ := os.ReadFile(m.SelfSignedCertPath())
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	get := func(rootCAs *x509.CertPool) (string, error) {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs, InsecureSkipVerify: rootCAs == nil}, DisableKeepAlives: true}}
		resp, err := c.Get("https://" + ln.Addr().String())
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		sum := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
		return hex.EncodeToString(sum[:]), nil
	}

	fp, err := get(pool)
	if err != nil || fp != m.Info().FingerprintSHA256 {
		t.Fatalf("verified handshake: %v %s", err, fp)
	}

	// Swap to a file-based certificate on the same listener.
	now := time.Now()
	crt, key := filepath.Join(dir, "c"), filepath.Join(dir, "k")
	newFP := writePair(t, crt, key, "rotated.test", now.Add(-time.Hour), now.Add(time.Hour*24))
	m.cfg.Mode, m.cfg.CertFile, m.cfg.KeyFile = config.TLSFile, crt, key
	if _, err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	if fp, err := get(nil); err != nil || fp != newFP {
		t.Fatalf("after rotation got %s, want %s (%v)", fp, newFP, err)
	}
}

func TestHosts(t *testing.T) {
	got := Hosts([]string{"Router.LAN", "localhost", " 10.0.0.5 "})
	want := []string{"localhost", "127.0.0.1", "::1", "router.lan", "10.0.0.5"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}
