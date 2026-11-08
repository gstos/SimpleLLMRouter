package config

import (
	"strings"
	"testing"
)

func base() *Config {
	c := &Config{APIKeys: []APIKey{{Name: "k", Hash: "sha256:" + strings.Repeat("0", 64)}}}
	return c
}

func TestTLSValidation(t *testing.T) {
	no := false
	cases := []struct {
		tls  TLS
		want string // substring of the error; "" = valid
	}{
		{TLS{}, ""},
		{TLS{Mode: TLSSelfSigned}, ""},
		{TLS{Mode: TLSFile, CertFile: "c", KeyFile: "k"}, ""},
		{TLS{Mode: TLSFile, CertFile: "c"}, "needs cert_file and key_file"},
		{TLS{Mode: "acme"}, "unknown mode"},
		{TLS{HTTPListen: ":80"}, "http_listen needs TLS"},
		{TLS{Mode: TLSSelfSigned, MinVersion: "1.1"}, "min_version"},
	}
	for _, c := range cases {
		cfg := base()
		cfg.Server.TLS = c.tls
		cfg.ApplyDefaults()
		err := cfg.Validate()
		if c.want == "" && err != nil {
			t.Errorf("%+v: unexpected error %v", c.tls, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%+v: error %v, want %q", c.tls, err, c.want)
		}
	}
	if !(TLS{}).Fallback() || (TLS{FallbackSelfSigned: &no}).Fallback() {
		t.Error("Fallback default should be true, and false when disabled")
	}
}
