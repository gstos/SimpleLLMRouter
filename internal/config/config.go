// Package config defines the router's YAML configuration and its validation.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/allowlist"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

// Model types, which determine the endpoints a model can be called on.
const (
	TypeChat      = "chat"
	TypeEmbedding = "embedding"
	TypeRerank    = "rerank"
	// TypeMessages: Anthropic Messages API (/v1/messages), routed natively to
	// providers that speak it. No format conversion: every target must accept
	// Anthropic requests.
	TypeMessages = "messages"
)

type Config struct {
	// MasterKeyCheck identifies the master key (see secrets.Cipher.KeyCheck).
	// Written by `provider add`; when set, a different master key is rejected.
	MasterKeyCheck string     `mapstructure:"master_key_check"`
	Server         Server     `mapstructure:"server"`
	Providers      []Provider `mapstructure:"providers"`
	Models         []Model    `mapstructure:"models"`
	APIKeys        []APIKey   `mapstructure:"api_keys"`
}

type Server struct {
	Listen          string        `mapstructure:"listen"`
	RequestTimeout  time.Duration `mapstructure:"request_timeout"`
	MaxBodyBytes    int64         `mapstructure:"max_body_bytes"`
	StickyTTL       time.Duration `mapstructure:"sticky_ttl"`
	FailureCooldown time.Duration `mapstructure:"failure_cooldown"`
	HealthInterval  time.Duration `mapstructure:"health_interval"`
	HealthTimeout   time.Duration `mapstructure:"health_timeout"`
	TLS             TLS           `mapstructure:"tls"`
	// AllowCIDRs restricts clients to these CIDRs or bare IPs (loopback is always
	// allowed). Empty allows everyone.
	AllowCIDRs []string `mapstructure:"allow_cidrs"`
	// TrustedProxies: peers whose X-Forwarded-For is used to find the client.
	TrustedProxies []string `mapstructure:"trusted_proxies"`
}

// TLS modes.
const (
	TLSOff        = "off"
	TLSFile       = "file"
	TLSSelfSigned = "self-signed"
	TLSACME       = "acme"
)

// ACME challenge types.
const (
	ChallengeHTTP = "http"
	ChallengeDNS  = "dns"
)

// ACME configures acme mode: the router runs lego (found in PATH) to obtain and
// renew the certificate. Options map to lego flags the router builds itself;
// no command, hook or LEGO_* variable can be set from here.
type ACME struct {
	Email   string   `mapstructure:"email"`
	Domains []string `mapstructure:"domains"`
	// Server: ACME directory URL or a lego shortcode (letsencrypt,
	// letsencrypt-staging, zerossl...). Default: letsencrypt.
	Server string `mapstructure:"server"`
	// CAFile: PEM bundle to trust for a private ACME server (step-ca, Pebble).
	CAFile string `mapstructure:"ca_file"`
	// KeyType: EC256 (default), EC384, RSA2048, RSA3072, RSA4096.
	KeyType string `mapstructure:"key_type"`

	// Challenge: "dns" (default; no inbound port, allows wildcards) or "http"
	// (needs server.tls.http_listen reachable on port 80 for every domain).
	Challenge string `mapstructure:"challenge"`
	// DNSProvider: lego provider code (cloudflare, route53, gcloud...); see `lego dnshelp`.
	DNSProvider string `mapstructure:"dns_provider"`
	// DNSEnv: the provider's credentials/settings as env vars for lego, e.g.
	// CLOUDFLARE_DNS_API_TOKEN. Values may be enc:v1: (decrypted with the master
	// key; `simple-router acme env set` writes them). LEGO_*, loader and shell
	// variables are refused.
	DNSEnv map[string]string `mapstructure:"dns_env"`
	// DNSResolvers: host:port resolvers for propagation checks (optional).
	DNSResolvers []string `mapstructure:"dns_resolvers"`
	// DNSPropagationWait: skip propagation checks and just wait this long (optional).
	DNSPropagationWait time.Duration `mapstructure:"dns_propagation_wait"`

	// CheckInterval: how often lego is run; it renews only when due (default 12h).
	CheckInterval time.Duration `mapstructure:"check_interval"`
}

func (a ACME) validate() []string {
	var errs []string
	if a.Email == "" {
		errs = append(errs, "email is required")
	}
	if len(a.Domains) == 0 {
		errs = append(errs, "at least one domain is required")
	}
	for _, d := range a.Domains {
		if strings.HasPrefix(d, "*.") && a.Challenge != ChallengeDNS {
			errs = append(errs, fmt.Sprintf("wildcard %q needs challenge dns", d))
		}
	}
	switch a.KeyType {
	case "EC256", "EC384", "RSA2048", "RSA3072", "RSA4096":
	default:
		errs = append(errs, fmt.Sprintf("unknown key_type %q", a.KeyType))
	}
	switch a.Challenge {
	case ChallengeDNS:
		if a.DNSProvider == "" {
			errs = append(errs, "dns_provider is required for challenge dns (see `lego dnshelp`)")
		}
		if a.DNSProvider != "" && !providerName.MatchString(a.DNSProvider) {
			errs = append(errs, fmt.Sprintf("invalid dns_provider %q", a.DNSProvider))
		}
		if a.DNSProvider == "exec" {
			errs = append(errs, "dns_provider exec runs a program and is not allowed")
		}
	case ChallengeHTTP:
		if len(a.DNSEnv) > 0 || a.DNSProvider != "" {
			errs = append(errs, "dns_provider/dns_env apply to challenge dns only")
		}
	default:
		errs = append(errs, fmt.Sprintf("unknown challenge %q (dns|http)", a.Challenge))
	}
	for name := range a.DNSEnv {
		if err := CheckLegoEnvName(name); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return errs
}

var (
	providerName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	envName      = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// CheckLegoEnvName refuses variables that could make lego (or the loader) run
// code or change its behaviour: LEGO_* (every lego flag, including hooks, can
// be set that way), dynamic loader variables, and process basics the router
// sets itself.
func CheckLegoEnvName(name string) error {
	if !envName.MatchString(name) {
		return fmt.Errorf("dns_env: %q is not a valid variable name (A-Z, 0-9, _)", name)
	}
	for _, p := range []string{"LEGO_", "LD_", "DYLD_", "SSL_", "EXEC_"} {
		if strings.HasPrefix(name, p) {
			return fmt.Errorf("dns_env: %s* variables are not allowed (%s)", p, name)
		}
	}
	switch name {
	case "GODEBUG", "GOGC", "GOMAXPROCS", "GOMEMLIMIT", "GOTRACEBACK", "GORACE", "GOFIPS140":
		// Go runtime settings of the lego binary (GODEBUG can relax TLS checks).
		// Other GO* names are allowed: GODADDY_*, GOOGLE_APPLICATION_CREDENTIALS...
		return fmt.Errorf("dns_env: %s (a Go runtime setting) is not allowed", name)
	case "PATH", "HOME", "SHELL", "IFS", "ENV", "BASH_ENV", "TMPDIR", "USER", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY":
		return fmt.Errorf("dns_env: %s is set by the router and cannot be overridden", name)
	}
	return nil
}

// LegoDir is where lego keeps its account and certificates, under the TLS dir.
const LegoDir = "lego"

type TLS struct {
	// Mode: off (default) | file | self-signed | acme.
	Mode string `mapstructure:"mode"`

	// file: PEM certificate (with chain) and key, written by any tool (lego,
	// certbot, cert-manager...). Re-read live when they change; a pair that
	// doesn't parse, match or is expired is ignored and the current one stays.
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	// file: serve a self-signed certificate until cert_file/key_file exist and
	// are valid (e.g. during the first ACME issuance). Default true.
	FallbackSelfSigned *bool `mapstructure:"fallback_self_signed"`

	// self-signed (and the fallback): names besides localhost, 127.0.0.1, ::1.
	Domains []string `mapstructure:"domains"`

	// Where the self-signed certificate is stored (0700). Default: "tls" next
	// to the config file.
	Dir string `mapstructure:"dir"`

	// Optional plain-HTTP listener (e.g. ":80") that redirects to HTTPS.
	HTTPListen string `mapstructure:"http_listen"`

	// MinVersion: "1.2" (default) or "1.3".
	MinVersion string `mapstructure:"min_version"`

	// ACME: settings for mode acme.
	ACME ACME `mapstructure:"acme"`
}

// Fallback reports whether file mode serves a self-signed certificate while
// the configured files are missing or invalid.
func (t TLS) Fallback() bool { return t.FallbackSelfSigned == nil || *t.FallbackSelfSigned }

// Enabled reports whether the router serves HTTPS.
func (t TLS) Enabled() bool { return t.Mode != TLSOff }

var headerName = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$") // RFC 9110 token

type Provider struct {
	Name    string `mapstructure:"name"`
	BaseURL string `mapstructure:"base_url"`
	// APIKey must be an "enc:v1:" value produced by `simple-router encrypt`.
	// May be empty for providers without auth (e.g. a local server).
	APIKey string `mapstructure:"api_key"`
	// AuthHeader defaults to "Authorization"; AuthScheme defaults to "Bearer".
	// Set auth_scheme to "none" to send the raw key (e.g. Azure's "api-key").
	AuthHeader string            `mapstructure:"auth_header"`
	AuthScheme string            `mapstructure:"auth_scheme"`
	Headers    map[string]string `mapstructure:"headers"`
	// Paths overrides the upstream path per endpoint (chat, completions, embeddings, rerank, health).
	Paths map[string]string `mapstructure:"paths"`
	// HealthMethod defaults to GET.
	HealthMethod string `mapstructure:"health_method"`
	// SessionHeader, when set, is sent on every upstream request with an id that
	// is stable for the conversation (derived from the sticky key), e.g.
	// X-Opencode-Session for OpenCode Go. A value the client sends in that
	// header is passed through instead.
	SessionHeader string `mapstructure:"session_header"`
	// Auth says whose credentials reach the provider. "managed" (default): the
	// client authenticates with a router key and the router sends api_key (if
	// any) with auth_header/auth_scheme. "passthrough": the router checks
	// nothing and forwards the client's own credentials; the provider is then
	// only reachable at /provider/<name>/ (not as a model target).
	Auth string `mapstructure:"auth"`
	// AllowPaths limits /provider/<name>/<path> to these paths: exact, or a
	// prefix ending in "*" (e.g. "/v1/*"). Empty allows every path.
	AllowPaths []string `mapstructure:"allow_paths"`
}

// Provider auth modes.
const (
	AuthManaged     = "managed"
	AuthPassthrough = "passthrough"
)

// PathAllowed reports whether /provider/ may forward to path (cleaned, absolute).
func (p *Provider) PathAllowed(path string) bool {
	if len(p.AllowPaths) == 0 {
		return true
	}
	for _, a := range p.AllowPaths {
		if prefix, ok := strings.CutSuffix(a, "*"); ok {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		} else if path == a {
			return true
		}
	}
	return false
}

// Provider returns the named provider, or nil.
func (c *Config) Provider(name string) *Provider {
	for i := range c.Providers {
		if c.Providers[i].Name == name {
			return &c.Providers[i]
		}
	}
	return nil
}

type Model struct {
	// Name is the model id clients send (e.g. "openai/gpt-4o").
	Name string `mapstructure:"name"`
	Type string `mapstructure:"type"`
	// Aliases are other ids clients may send for this model (e.g. "baai/bge-m3"
	// for "bge-m3"): same targets, routing and sticky sessions.
	Aliases []string `mapstructure:"aliases"`
	Targets []Target `mapstructure:"targets"`
}

type Target struct {
	Provider string `mapstructure:"provider"`
	// Model is the upstream model id; defaults to the public model name.
	Model string `mapstructure:"model"`
	// Priority: lower is tried first. Equal priorities are round-robined.
	Priority int `mapstructure:"priority"`
}

type APIKey struct {
	Name string `mapstructure:"name"`
	// Hash is "sha256:<hex>" of the client key, produced by `simple-router apikey`.
	Hash string `mapstructure:"hash"`
	// Models the key may use; glob patterns allowed. Empty or ["*"] means all.
	Models []string `mapstructure:"models"`
	// Admin keys may call /admin endpoints (provider health).
	Admin bool `mapstructure:"admin"`
	// Providers the key may reach directly at /provider/<name>/ (auth: managed
	// providers; glob patterns allowed, "*" = all). Empty means none.
	Providers []string `mapstructure:"providers"`
}

// Endpoint names used for path lookup.
const (
	EndpointChat        = "chat"
	EndpointCompletions = "completions"
	EndpointEmbeddings  = "embeddings"
	EndpointRerank      = "rerank"
	EndpointMessages    = "messages"
	EndpointCountTokens = "count_tokens"
	EndpointHealth      = "health"
)

var defaultPaths = map[string]string{
	EndpointChat:        "/chat/completions",
	EndpointCompletions: "/completions",
	EndpointEmbeddings:  "/embeddings",
	EndpointRerank:      "/rerank",
	EndpointMessages:    "/messages",
	EndpointCountTokens: "/messages/count_tokens",
	EndpointHealth:      "/models",
}

// Path returns the upstream path for an endpoint.
func (p Provider) Path(endpoint string) string {
	if v, ok := p.Paths[endpoint]; ok && v != "" {
		return v
	}
	return defaultPaths[endpoint]
}

// ApplyDefaults fills in unset values.
func (c *Config) ApplyDefaults() {
	s := &c.Server
	if s.Listen == "" {
		s.Listen = ":8080"
	}
	if s.RequestTimeout == 0 {
		s.RequestTimeout = 5 * time.Minute
	}
	if s.MaxBodyBytes == 0 {
		s.MaxBodyBytes = 32 << 20
	}
	if s.StickyTTL == 0 {
		s.StickyTTL = 10 * time.Minute
	}
	if s.FailureCooldown == 0 {
		s.FailureCooldown = 30 * time.Second
	}
	if s.HealthTimeout == 0 {
		s.HealthTimeout = 10 * time.Second
	}
	if s.TLS.Mode == "" {
		s.TLS.Mode = TLSOff
	}
	if s.TLS.MinVersion == "" {
		s.TLS.MinVersion = "1.2"
	}
	if env := s.TLS.ACME.DNSEnv; len(env) > 0 {
		// Viper lowercases map keys; provider variables are uppercase by convention.
		up := make(map[string]string, len(env))
		for k, v := range env {
			up[strings.ToUpper(k)] = v
		}
		s.TLS.ACME.DNSEnv = up
	}
	if a := &s.TLS.ACME; s.TLS.Mode == TLSACME {
		if a.Server == "" {
			a.Server = "letsencrypt"
		}
		if a.KeyType == "" {
			a.KeyType = "EC256"
		}
		if a.Challenge == "" {
			a.Challenge = ChallengeDNS
		}
		if a.CheckInterval == 0 {
			a.CheckInterval = 12 * time.Hour
		}
	}
	for i := range c.Providers {
		p := &c.Providers[i]
		p.BaseURL = strings.TrimRight(p.BaseURL, "/")
		if p.Auth == "" {
			p.Auth = AuthManaged
		}
		if p.Auth == AuthPassthrough {
			// The client's own credentials go through: nothing to default (and
			// Validate refuses api_key/auth_header/auth_scheme here).
			if p.HealthMethod == "" {
				p.HealthMethod = "GET"
			}
			continue
		}
		if p.AuthHeader == "" {
			p.AuthHeader = "Authorization"
		}
		if p.AuthScheme == "" {
			p.AuthScheme = "Bearer"
		}
		if p.HealthMethod == "" {
			p.HealthMethod = "GET"
		}
	}
	for i := range c.Models {
		m := &c.Models[i]
		if m.Type == "" {
			m.Type = TypeChat
		}
		for j := range m.Targets {
			if m.Targets[j].Model == "" {
				m.Targets[j].Model = m.Name
			}
		}
	}
}

// Validate checks structural consistency. It does not decrypt secrets.
func (c *Config) Validate() error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	if _, err := allowlist.Parse(c.Server.AllowCIDRs, c.Server.TrustedProxies); err != nil {
		add("%s", err)
	}

	t := c.Server.TLS
	switch t.Mode {
	case TLSOff:
	case TLSFile:
		if t.CertFile == "" || t.KeyFile == "" {
			add("server.tls: mode file needs cert_file and key_file")
		}
	case TLSSelfSigned:
	case TLSACME:
		for _, e := range t.ACME.validate() {
			add("server.tls.acme: %s", e)
		}
		if t.ACME.Challenge == ChallengeHTTP && t.HTTPListen == "" {
			add("server.tls.acme: challenge http needs server.tls.http_listen (reachable on port 80)")
		}
	default:
		add("server.tls: unknown mode %q (off|file|self-signed|acme)", t.Mode)
	}
	if t.HTTPListen != "" && !t.Enabled() {
		add("server.tls: http_listen needs TLS enabled")
	}
	if t.MinVersion != "1.2" && t.MinVersion != "1.3" {
		add("server.tls: min_version must be \"1.2\" or \"1.3\"")
	}

	providers := map[string]bool{}
	passthrough := map[string]bool{}
	for i, p := range c.Providers {
		switch {
		case p.Name == "":
			add("providers[%d]: name is required", i)
		case providers[p.Name]:
			add("providers[%d]: duplicate name %q", i, p.Name)
		case strings.Contains(p.Name, "/"):
			add("provider %q: name must not contain \"/\"", p.Name)
		}
		providers[p.Name] = true
		if u, err := url.Parse(p.BaseURL); err != nil || u.Scheme == "" || u.Host == "" {
			add("provider %q: base_url %q is not an absolute URL", p.Name, p.BaseURL)
		}
		if p.APIKey != "" && !secrets.IsEncrypted(p.APIKey) {
			add("provider %q: api_key must be encrypted (use `simple-router encrypt`)", p.Name)
		}
		if p.SessionHeader != "" && !headerName.MatchString(p.SessionHeader) {
			add("provider %q: session_header %q is not a valid header name", p.Name, p.SessionHeader)
		}
		switch p.Auth {
		case AuthManaged:
		case AuthPassthrough:
			passthrough[p.Name] = true
			if p.APIKey != "" || p.AuthHeader != "" || p.AuthScheme != "" {
				add("provider %q: api_key, auth_header and auth_scheme don't apply with auth: passthrough (the client's credentials are forwarded)", p.Name)
			}
		default:
			add("provider %q: unknown auth %q (managed|passthrough)", p.Name, p.Auth)
		}
		for _, a := range p.AllowPaths {
			if !strings.HasPrefix(a, "/") || strings.Contains(strings.TrimSuffix(a, "*"), "*") {
				add("provider %q: allow_paths entry %q must start with \"/\" (\"*\" only at the end)", p.Name, a)
			}
		}
	}

	models := map[string]bool{}
	for i, m := range c.Models {
		switch {
		case m.Name == "":
			add("models[%d]: name is required", i)
		case models[m.Name]:
			add("models[%d]: duplicate name %q", i, m.Name)
		}
		models[m.Name] = true
		switch m.Type {
		case TypeChat, TypeEmbedding, TypeRerank, TypeMessages:
		default:
			add("model %q: unknown type %q (chat|embedding|rerank|messages)", m.Name, m.Type)
		}
		for _, a := range m.Aliases {
			switch {
			case a == "":
				add("model %q: empty alias", m.Name)
			case a == m.Name:
				add("model %q: alias %q is the model's own name", m.Name, a)
			case models[a]:
				add("model %q: alias %q is already a model name or alias", m.Name, a)
			}
			models[a] = true
		}
		if len(m.Targets) == 0 {
			add("model %q: at least one target is required", m.Name)
		}
		for _, t := range m.Targets {
			if !providers[t.Provider] {
				add("model %q: unknown provider %q", m.Name, t.Provider)
			} else if passthrough[t.Provider] {
				add("model %q: provider %q has auth: passthrough and can only be used at /provider/%s/", m.Name, t.Provider, t.Provider)
			}
		}
	}

	keyNames := map[string]bool{}
	for i, k := range c.APIKeys {
		if k.Name == "" {
			add("api_keys[%d]: name is required", i)
		} else if keyNames[k.Name] {
			add("api_keys[%d]: duplicate name %q", i, k.Name)
		}
		keyNames[k.Name] = true
		if !strings.HasPrefix(k.Hash, "sha256:") || len(k.Hash) != len("sha256:")+64 {
			add("api key %q: hash must be sha256:<64 hex chars> (use `simple-router apikey`)", k.Name)
		}
		for _, pat := range k.Models {
			if _, err := path.Match(pat, ""); err != nil {
				add("api key %q: bad model pattern %q", k.Name, pat)
			}
		}
	}
	if c.MasterKeyCheck != "" && (!strings.HasPrefix(c.MasterKeyCheck, secrets.CheckPrefix) || len(c.MasterKeyCheck) != len(secrets.CheckPrefix)+32) {
		add("master_key_check: malformed (expected %s<32 hex chars>)", secrets.CheckPrefix)
	}
	if len(c.APIKeys) == 0 {
		add("api_keys: at least one key is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid config:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// ErrWrongMasterKey means the master key doesn't match master_key_check.
var ErrWrongMasterKey = errors.New("wrong master key: it does not match master_key_check in the config")

// DecryptSecrets replaces every provider api_key with its plaintext.
func (c *Config) DecryptSecrets(ci *secrets.Cipher) error {
	if c.MasterKeyCheck != "" && !ci.VerifyKeyCheck(c.MasterKeyCheck) {
		return ErrWrongMasterKey
	}
	for i := range c.Providers {
		p := &c.Providers[i]
		if p.APIKey == "" {
			continue
		}
		pt, err := ci.Decrypt(p.APIKey)
		if err != nil {
			return fmt.Errorf("provider %q: %w", p.Name, err)
		}
		p.APIKey = pt
	}
	env := c.Server.TLS.ACME.DNSEnv
	for name, val := range env {
		if !secrets.IsEncrypted(val) {
			continue
		}
		pt, err := ci.Decrypt(val)
		if err != nil {
			return fmt.Errorf("server.tls.acme.dns_env %s: %w", name, err)
		}
		env[name] = pt
	}
	return nil
}
