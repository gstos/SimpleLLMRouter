// Package upstream builds the HTTP transports used to reach providers.
package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/gstos/SimpleLLMRouter/internal/config"
)

// ErrRedirect is returned for any upstream redirect: they are never followed.
var ErrRedirect = errors.New("upstream redirects are not allowed")

// NoRedirects is an http.Client CheckRedirect that refuses every redirect.
func NoRedirects(*http.Request, []*http.Request) error { return ErrRedirect }

// Transport returns a clone of the default transport. With a ca_file the
// provider's TLS trusts only that bundle. When the file can't be read (it
// changed after validation) the transport trusts nothing, so requests fail
// closed, and the error is returned for logging.
func Transport(p *config.Provider) (*http.Transport, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if p.CAFile == "" {
		return tr, nil
	}
	pool, err := config.LoadCAPool(p.CAFile)
	if err != nil {
		pool = x509.NewCertPool()
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return tr, err
}

// Transports builds one transport per provider that has a ca_file, keyed by
// provider name; other providers use the shared default. onErr (optional) is
// called for providers whose ca_file couldn't be loaded.
func Transports(providers []config.Provider, onErr func(provider string, err error)) map[string]*http.Transport {
	out := map[string]*http.Transport{}
	for i := range providers {
		p := &providers[i]
		if p.CAFile == "" {
			continue
		}
		tr, err := Transport(p)
		if err != nil && onErr != nil {
			onErr(p.Name, err)
		}
		out[p.Name] = tr
	}
	return out
}
