package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/tlsconf"
)

var (
	clientCAFile   string
	clientInsecure bool
)

func addClientTLSFlags(c *cobra.Command) {
	c.Flags().StringVar(&clientCAFile, "ca-file", "", "PEM CA (or certificate) to trust for the router's HTTPS certificate")
	c.Flags().BoolVar(&clientInsecure, "insecure", false, "skip certificate verification (only allowed for localhost URLs)")
}

// clientTLS builds the client TLS config for calls that send the master key.
// It verifies the certificate, trusting the system roots, --ca-file, and the
// router's own self-signed certificate when cfg is known. For a local router
// in file mode, it checks the certificate against the name it was issued for,
// since a public certificate doesn't cover 127.0.0.1.
func clientTLS(rawURL string, cfg *config.Config) (*tls.Config, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return nil, err
	}
	local := isLocalURL(rawURL)
	if clientInsecure {
		if !local {
			return nil, errors.New("--insecure is only allowed for localhost URLs")
		}
		return &tls.Config{InsecureSkipVerify: true}, nil //nolint:gosec // explicit opt-in, loopback only
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if clientCAFile != "" {
		b, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("%s: no PEM certificates found", clientCAFile)
		}
	}
	tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if cfg == nil || !cfg.Server.TLS.Enabled() {
		return tc, nil
	}

	base := filepath.Dir(v.GetString("config"))
	if b, err := os.ReadFile(filepath.Join(tlsconf.Dir(cfg.Server.TLS, base), tlsconf.SelfSignedCert)); err == nil {
		pool.AppendCertsFromPEM(b) // self-signed mode, or the file-mode fallback
	}
	if local {
		certFile := ""
		switch cfg.Server.TLS.Mode {
		case config.TLSFile:
			certFile = resolvePath(base, cfg.Server.TLS.CertFile)
		case config.TLSACME:
			certFile, _ = tlsconf.ACMEPaths(tlsconf.Dir(cfg.Server.TLS, base))
		}
		if name := certName(certFile); name != "" {
			tc.ServerName = name
		}
	}
	return tc, nil
}

// certName returns the first DNS name of the leaf certificate at path, or ""
// if it can't be read, has no DNS names, or already covers 127.0.0.1.
func certName(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(b) // the leaf comes first in a chain file
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return "" // not served: the router falls back to its self-signed certificate
	}
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			return ""
		}
	}
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames[0]
	}
	return ""
}

func resolvePath(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}
