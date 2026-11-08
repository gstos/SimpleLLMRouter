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
		{TLS{Mode: "bogus"}, "unknown mode"},
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

func TestACMEValidation(t *testing.T) {
	ok := ACME{Email: "a@b.c", Domains: []string{"x.test"}, DNSProvider: "cloudflare",
		DNSEnv: map[string]string{"cloudflare_dns_api_token": "enc:v1:x"}} // viper lowercases keys
	cases := []struct {
		mod  func(*TLS)
		want string
	}{
		{func(t *TLS) {}, ""},
		{func(t *TLS) { t.ACME.Email = "" }, "email is required"},
		{func(t *TLS) { t.ACME.Domains = nil }, "at least one domain"},
		{func(t *TLS) { t.ACME.DNSProvider = "" }, "dns_provider is required"},
		{func(t *TLS) { t.ACME.DNSProvider = "exec" }, "not allowed"},
		{func(t *TLS) { t.ACME.DNSEnv = map[string]string{"LEGO_DEPLOY_HOOK": "x"} }, "LEGO_* variables are not allowed"},
		{func(t *TLS) { t.ACME.DNSEnv = map[string]string{"LD_PRELOAD": "x"} }, "LD_* variables"},
		{func(t *TLS) { t.ACME.Challenge = ChallengeHTTP; t.ACME.DNSProvider = ""; t.ACME.DNSEnv = nil }, "needs server.tls.http_listen"},
		{func(t *TLS) {
			t.ACME.Challenge = ChallengeHTTP
			t.ACME.DNSProvider = ""
			t.ACME.DNSEnv = nil
			t.ACME.Domains = []string{"*.x.test"}
			t.HTTPListen = ":80"
		}, "needs challenge dns"},
		{func(t *TLS) { t.ACME.KeyType = "DSA" }, "unknown key_type"},
	}
	for i, c := range cases {
		cfg := base()
		cfg.Server.TLS = TLS{Mode: TLSACME, ACME: ok}
		cfg.Server.TLS.ACME.DNSEnv = map[string]string{}
		for k, v := range ok.DNSEnv {
			cfg.Server.TLS.ACME.DNSEnv[k] = v
		}
		c.mod(&cfg.Server.TLS)
		cfg.ApplyDefaults()
		err := cfg.Validate()
		if c.want == "" && err != nil {
			t.Errorf("case %d: unexpected %v", i, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("case %d: error %v, want %q", i, err, c.want)
		}
	}
	cfg := base()
	cfg.Server.TLS = TLS{Mode: TLSACME, ACME: ok}
	cfg.ApplyDefaults()
	if _, ok := cfg.Server.TLS.ACME.DNSEnv["CLOUDFLARE_DNS_API_TOKEN"]; !ok {
		t.Error("dns_env keys not uppercased")
	}
	if a := cfg.Server.TLS.ACME; a.Server != "letsencrypt" || a.Challenge != ChallengeDNS || a.KeyType != "EC256" || a.CheckInterval == 0 {
		t.Errorf("defaults: %+v", a)
	}
}

func TestSessionHeaderValidation(t *testing.T) {
	for h, ok := range map[string]bool{"X-Opencode-Session": true, "x-session": true, "Bad Header": false, "a:b": false, "x\r\ny": false} {
		cfg := base()
		cfg.Providers = []Provider{{Name: "p", BaseURL: "https://x.test/v1", SessionHeader: h}}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		if ok != (err == nil) {
			t.Errorf("%q: %v", h, err)
		}
	}
}

func TestAliasValidation(t *testing.T) {
	model := func(name string, aliases ...string) Model {
		return Model{Name: name, Aliases: aliases, Targets: []Target{{Provider: "p", Model: "m"}}}
	}
	cases := []struct {
		models []Model
		want   string
	}{
		{[]Model{model("a", "x", "y"), model("b", "z")}, ""},
		{[]Model{model("a", "")}, "empty alias"},
		{[]Model{model("a", "a")}, "own name"},
		{[]Model{model("a", "x"), model("b", "x")}, "already a model name or alias"},
		{[]Model{model("a", "b"), model("b")}, "duplicate name"},
		{[]Model{model("a"), model("b", "a")}, "already a model name or alias"},
	}
	for i, c := range cases {
		cfg := base()
		cfg.Providers = []Provider{{Name: "p", BaseURL: "https://x.test/v1"}}
		cfg.Models = c.models
		cfg.ApplyDefaults()
		err := cfg.Validate()
		if c.want == "" && err != nil {
			t.Errorf("case %d: %v", i, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("case %d: %v, want %q", i, err, c.want)
		}
	}
}

func TestProviderAuthValidation(t *testing.T) {
	cases := []struct {
		p    Provider
		m    []Model
		want string
	}{
		{Provider{Auth: AuthPassthrough}, nil, ""},
		{Provider{}, []Model{{Name: "x", Targets: []Target{{Provider: "p", Model: "m"}}}}, ""},
		{Provider{Auth: AuthPassthrough, APIKey: "enc:v1:x"}, nil, "don't apply with auth: passthrough"},
		{Provider{Auth: AuthPassthrough, AuthHeader: "api-key"}, nil, "don't apply with auth: passthrough"},
		{Provider{Auth: AuthPassthrough}, []Model{{Name: "x", Targets: []Target{{Provider: "p", Model: "m"}}}}, "can only be used at /provider/p/"},
		{Provider{Auth: "open"}, nil, "unknown auth"},
		{Provider{AllowPaths: []string{"v1/*"}}, nil, "allow_paths"},
		{Provider{AllowPaths: []string{"/v1/*/x"}}, nil, "allow_paths"},
		{Provider{AllowPaths: []string{"/v1/*", "/health"}}, nil, ""},
	}
	for i, c := range cases {
		cfg := base()
		c.p.Name, c.p.BaseURL = "p", "https://x.test/v1"
		cfg.Providers = []Provider{c.p}
		cfg.Models = c.m
		cfg.ApplyDefaults()
		err := cfg.Validate()
		if c.want == "" && err != nil {
			t.Errorf("case %d: %v", i, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("case %d: %v, want %q", i, err, c.want)
		}
	}
	cfg := base()
	cfg.Providers = []Provider{{Name: "p", BaseURL: "https://x.test"}}
	cfg.ApplyDefaults()
	if p := cfg.Providers[0]; p.Auth != AuthManaged || p.AuthHeader != "Authorization" {
		t.Fatalf("defaults: %+v", p)
	}
}

func TestLegoEnvNameGoPrefix(t *testing.T) {
	for _, ok := range []string{"GODADDY_API_KEY", "GODADDY_API_SECRET", "GOOGLE_APPLICATION_CREDENTIALS", "GCE_PROJECT"} {
		if err := CheckLegoEnvName(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"GODEBUG", "GOMAXPROCS", "GOTRACEBACK", "LEGO_HOOK", "LD_PRELOAD"} {
		if CheckLegoEnvName(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
