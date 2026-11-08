// Package config defines the router's YAML configuration and its validation.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/secrets"
)

// Model types, which determine the endpoints a model can be called on.
const (
	TypeChat      = "chat"
	TypeEmbedding = "embedding"
	TypeRerank    = "rerank"
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
}

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
}

type Model struct {
	// Name is the model id clients send (e.g. "openai/gpt-4o").
	Name    string   `mapstructure:"name"`
	Type    string   `mapstructure:"type"`
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
}

// Endpoint names used for path lookup.
const (
	EndpointChat        = "chat"
	EndpointCompletions = "completions"
	EndpointEmbeddings  = "embeddings"
	EndpointRerank      = "rerank"
	EndpointHealth      = "health"
)

var defaultPaths = map[string]string{
	EndpointChat:        "/chat/completions",
	EndpointCompletions: "/completions",
	EndpointEmbeddings:  "/embeddings",
	EndpointRerank:      "/rerank",
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
	for i := range c.Providers {
		p := &c.Providers[i]
		p.BaseURL = strings.TrimRight(p.BaseURL, "/")
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

	providers := map[string]bool{}
	for i, p := range c.Providers {
		switch {
		case p.Name == "":
			add("providers[%d]: name is required", i)
		case providers[p.Name]:
			add("providers[%d]: duplicate name %q", i, p.Name)
		}
		providers[p.Name] = true
		if u, err := url.Parse(p.BaseURL); err != nil || u.Scheme == "" || u.Host == "" {
			add("provider %q: base_url %q is not an absolute URL", p.Name, p.BaseURL)
		}
		if p.APIKey != "" && !secrets.IsEncrypted(p.APIKey) {
			add("provider %q: api_key must be encrypted (use `simple-router encrypt`)", p.Name)
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
		case TypeChat, TypeEmbedding, TypeRerank:
		default:
			add("model %q: unknown type %q (chat|embedding|rerank)", m.Name, m.Type)
		}
		if len(m.Targets) == 0 {
			add("model %q: at least one target is required", m.Name)
		}
		for _, t := range m.Targets {
			if !providers[t.Provider] {
				add("model %q: unknown provider %q", m.Name, t.Provider)
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
	return nil
}
