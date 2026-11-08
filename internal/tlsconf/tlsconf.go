// Package tlsconf provides the router's TLS certificate, swappable at runtime.
//
// The server reads the certificate through tls.Config.GetCertificate on every
// handshake, so replacing it never needs a restart: new connections get the new
// certificate, existing ones carry on.
//
// Modes:
//   - file: a certificate/key pair written by any tool (lego, certbot,
//     cert-manager...). Reload re-reads it; a pair that doesn't parse, whose key
//     doesn't match, or that is expired is rejected and the current one stays.
//     Until a valid pair exists, a self-signed fallback can be served.
//   - self-signed: generated on first use, stored in Dir so clients can trust
//     it, and regenerated before it expires or when the names change.
package tlsconf

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/config"
)

const (
	// SelfSignedCert and SelfSignedKey are the file names inside Dir.
	SelfSignedCert = "selfsigned.crt"
	SelfSignedKey  = "selfsigned.key"

	selfSignedValidity = 365 * 24 * time.Hour
	selfSignedRenew    = 30 * 24 * time.Hour // regenerate when this close to expiry
	expiryWarning      = 14 * 24 * time.Hour
)

// Info describes the certificate being served.
type Info struct {
	Source            string    `json:"source"` // "file", "self-signed" or "fallback"
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	DNSNames          []string  `json:"dns_names,omitempty"`
	IPAddresses       []string  `json:"ip_addresses,omitempty"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	LoadedAt          time.Time `json:"loaded_at"`
}

type served struct {
	cert *tls.Certificate
	info Info
}

// Manager holds the current certificate.
type Manager struct {
	cfg config.TLS
	dir string
	log *slog.Logger
	now func() time.Time

	cur atomic.Pointer[served]

	mu         sync.Mutex // serialises Reload
	lastWarned time.Time  // expiry warning
	lastErr    string     // last periodic reload failure, to avoid repeating it every minute
	lastErrAt  time.Time
}

// New loads (or generates) the initial certificate. baseDir resolves relative
// paths (normally the config file's directory).
func New(cfg config.TLS, baseDir string, log *slog.Logger) (*Manager, error) {
	if !cfg.Enabled() {
		return nil, errors.New("tls is off")
	}
	m := &Manager{cfg: cfg, log: log, now: time.Now}
	m.cfg.CertFile = resolve(baseDir, cfg.CertFile)
	m.cfg.KeyFile = resolve(baseDir, cfg.KeyFile)
	m.dir = Dir(cfg, baseDir)

	switch cfg.Mode {
	case config.TLSFile:
		if err := m.loadFile(); err != nil {
			if !cfg.Fallback() {
				return nil, err
			}
			log.Warn("TLS certificate not usable yet; serving a self-signed fallback until it is", "err", err)
			if err := m.ensureSelfSigned("fallback"); err != nil {
				return nil, err
			}
		}
	case config.TLSSelfSigned:
		if err := m.ensureSelfSigned("self-signed"); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported tls mode %q", cfg.Mode)
	}
	return m, nil
}

// TLSConfig returns a server config that always serves the current certificate.
func (m *Manager) TLSConfig() *tls.Config {
	minVersion := uint16(tls.VersionTLS12)
	if m.cfg.MinVersion == "1.3" {
		minVersion = tls.VersionTLS13
	}
	return &tls.Config{
		MinVersion: minVersion,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return m.cur.Load().cert, nil
		},
	}
}

// Info describes the certificate being served.
func (m *Manager) Info() Info { return m.cur.Load().info }

// WatchFiles lists the files whose changes should trigger Reload.
func (m *Manager) WatchFiles() []string {
	if m.cfg.Mode == config.TLSFile {
		return []string{m.cfg.CertFile, m.cfg.KeyFile}
	}
	return nil
}

// Dir returns the certificate directory for cfg (baseDir: the config's directory).
func Dir(cfg config.TLS, baseDir string) string {
	if cfg.Dir == "" {
		return filepath.Join(baseDir, "tls")
	}
	return resolve(baseDir, cfg.Dir)
}

// SelfSignedCertPath is where the self-signed (or fallback) certificate lives.
func (m *Manager) SelfSignedCertPath() string { return filepath.Join(m.dir, SelfSignedCert) }

// Reload re-reads the certificate files (file mode) or renews the self-signed
// certificate when due. On error the current certificate keeps being served.
// It reports whether the served certificate changed.
func (m *Manager) Reload() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	before := m.cur.Load().info.FingerprintSHA256

	var err error
	switch {
	case m.cfg.Mode == config.TLSFile:
		err = m.loadFile()
		if err != nil && m.cur.Load().info.Source == "fallback" {
			err = errors.Join(err, m.ensureSelfSigned("fallback")) // keep the fallback fresh
		}
	default:
		err = m.ensureSelfSigned("self-signed")
	}
	changed := m.cur.Load().info.FingerprintSHA256 != before
	if changed {
		i := m.Info()
		m.log.Info("TLS certificate loaded", "source", i.Source, "subject", i.Subject,
			"not_after", i.NotAfter, "fingerprint_sha256", i.FingerprintSHA256)
	}
	return changed, err
}

// Check renews/reloads if needed and warns when the certificate expires soon.
// Call it periodically (it also covers missed file events).
func (m *Manager) Check() {
	if _, err := m.Reload(); err != nil {
		msg := err.Error()
		if msg != m.lastErr || m.now().Sub(m.lastErrAt) > time.Hour {
			m.lastErr, m.lastErrAt = msg, m.now()
			if m.Info().Source == "fallback" {
				m.log.Info("still waiting for a valid TLS certificate; serving the self-signed fallback", "err", msg)
			} else {
				m.log.Warn("TLS certificate reload failed; keeping the current one", "err", msg)
			}
		}
	} else {
		m.lastErr = ""
	}
	i := m.Info()
	left := i.NotAfter.Sub(m.now())
	if i.Source == "file" && left < expiryWarning && m.now().Sub(m.lastWarned) > 24*time.Hour {
		m.lastWarned = m.now()
		m.log.Warn("TLS certificate expires soon", "not_after", i.NotAfter, "left", left.Round(time.Hour).String())
	}
}

// loadFile validates the configured pair and swaps it in.
func (m *Manager) loadFile() error {
	cert, err := tls.LoadX509KeyPair(m.cfg.CertFile, m.cfg.KeyFile) // also checks the key matches
	if err != nil {
		return fmt.Errorf("loading %s / %s: %w", m.cfg.CertFile, m.cfg.KeyFile, err)
	}
	if err := m.checkValidity(cert.Leaf); err != nil {
		return fmt.Errorf("%s: %w", m.cfg.CertFile, err)
	}
	m.swap(&cert, "file")
	return nil
}

func (m *Manager) checkValidity(leaf *x509.Certificate) error {
	now := m.now()
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("certificate expired on %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if now.Add(5 * time.Minute).Before(leaf.NotBefore) { // small allowance for clock skew
		return fmt.Errorf("certificate not valid until %s", leaf.NotBefore.Format(time.RFC3339))
	}
	return nil
}

func (m *Manager) swap(cert *tls.Certificate, source string) {
	leaf := cert.Leaf
	sum := sha256.Sum256(leaf.Raw)
	info := Info{
		Source:            source,
		Subject:           leaf.Subject.String(),
		Issuer:            leaf.Issuer.String(),
		DNSNames:          leaf.DNSNames,
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		LoadedAt:          m.now(),
	}
	for _, ip := range leaf.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	if prev := m.cur.Load(); prev != nil && prev.info.FingerprintSHA256 == info.FingerprintSHA256 {
		info.LoadedAt = prev.info.LoadedAt // unchanged: keep the original load time
	}
	m.cur.Store(&served{cert: cert, info: info})
}

func resolve(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

// Hosts returns the names a self-signed certificate covers.
func Hosts(domains []string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	seen := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	for _, d := range domains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d != "" && !seen[d] {
			seen[d] = true
			hosts = append(hosts, d)
		}
	}
	return hosts
}

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
