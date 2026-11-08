package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"
)

// ensureSelfSigned serves the stored self-signed certificate, generating a new
// one when it is missing, unreadable, close to expiry or covers other names.
// source is "self-signed" or "fallback". A no-op when that certificate is
// already being served and still fine.
func (m *Manager) ensureSelfSigned(source string) error {
	certPath := filepath.Join(m.dir, SelfSignedCert)
	keyPath := filepath.Join(m.dir, SelfSignedKey)
	hosts := Hosts(m.cfg.Domains)

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && m.selfSignedUsable(cert.Leaf, hosts) {
		if cur := m.cur.Load(); cur == nil || cur.info.Source != source || !slices.Equal(cur.cert.Leaf.Raw, cert.Leaf.Raw) {
			m.swap(&cert, source)
		}
		return nil
	}

	cert, err := m.generateSelfSigned(hosts, certPath, keyPath)
	if err != nil {
		return fmt.Errorf("generating self-signed certificate: %w", err)
	}
	m.swap(cert, source)
	m.log.Info("generated self-signed TLS certificate", "path", certPath, "hosts", hosts,
		"not_after", cert.Leaf.NotAfter, "fingerprint_sha256", m.Info().FingerprintSHA256)
	return nil
}

func (m *Manager) selfSignedUsable(leaf *x509.Certificate, hosts []string) bool {
	if m.now().Add(selfSignedRenew).After(leaf.NotAfter) {
		return false
	}
	have := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		have = append(have, ip.String())
	}
	want := append([]string{}, hosts...)
	sort.Strings(have)
	sort.Strings(want)
	return slices.Equal(have, want)
}

func (m *Manager) generateSelfSigned(hosts []string, certPath, keyPath string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := m.now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "simple-router self-signed", Organization: []string{"simple-router"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(selfSignedValidity),
		// It is its own trust anchor: clients add this certificate as a CA.
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, err
	}
	// Key first: a reader never sees a new certificate next to an old key for long,
	// and LoadX509KeyPair rejects a mismatch anyway.
	if err := writeAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
