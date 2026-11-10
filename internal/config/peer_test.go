package config

import (
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPeerExternalCAFileValidation(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	good := filepath.Join(dir, "good.pem")
	_ = os.WriteFile(good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	junk := filepath.Join(dir, "junk.pem")
	_ = os.WriteFile(junk, []byte("not a certificate"), 0o600)
	enc := "enc:v1:AAAA"

	for _, tc := range []struct {
		name string
		p    Provider
		err  string // "" = valid
	}{
		{"plain peer", Provider{Peer: true}, ""},
		{"peer with ca_file", Provider{Peer: true, CAFile: good}, ""},
		{"external", Provider{External: true, APIKey: enc}, ""},
		{"local with ca_file", Provider{CAFile: good}, ""},
		{"peer api_key", Provider{Peer: true, APIKey: enc}, "don't apply to a peer"},
		{"peer auth_header", Provider{Peer: true, AuthHeader: "X-Key"}, "don't apply to a peer"},
		{"peer auth_scheme", Provider{Peer: true, AuthScheme: "none"}, "don't apply to a peer"},
		{"peer external", Provider{Peer: true, External: true}, "can't also be external"},
		{"peer passthrough", Provider{Peer: true, Auth: AuthPassthrough}, "can't use auth: passthrough"},
		{"missing ca_file", Provider{CAFile: filepath.Join(dir, "none.pem")}, `provider "p": ca_file`},
		{"junk ca_file", Provider{CAFile: junk}, "no PEM certificates"},
	} {
		cfg := base()
		tc.p.Name, tc.p.BaseURL = "p", "https://p.test/v1"
		cfg.Providers = []Provider{tc.p}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s: want %q, got %v", tc.name, tc.err, err)
		}
	}
}

func TestPeerTargetModelDefaultsAndHealthURL(t *testing.T) {
	cfg := base()
	cfg.Providers = []Provider{{Name: "rb", BaseURL: "https://rb.lan:8443/v1/", Peer: true}}
	cfg.Models = []Model{{Name: "m", Targets: []Target{{Provider: "rb"}}}}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Models[0].Targets[0].Model; got != "m" {
		t.Errorf("target model %q, want m", got)
	}
	if got := cfg.Providers[0].HealthURL(); got != "https://rb.lan:8443/healthz" {
		t.Errorf("health url %q", got)
	}
}
