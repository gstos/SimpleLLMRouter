package config

import (
	"strings"
	"testing"
)

func TestBaseURLsValidation(t *testing.T) {
	for _, tc := range []struct {
		urls map[string]string
		err  string // "" = valid
	}{
		{map[string]string{"chat": "https://opencode.ai/inference/systemone/v1"}, ""},
		{map[string]string{"health": "https://OPENCODE.ai/other/"}, ""}, // host is case-insensitive
		{map[string]string{"chat": "https://evil.test/v1"}, "same scheme and host"},
		{map[string]string{"chat": "http://opencode.ai/v1"}, "same scheme and host"},
		{map[string]string{"chat": "https://opencode.ai:8443/v1"}, "same scheme and host"},
		{map[string]string{"chat": "https://u:p@opencode.ai/v1"}, "credentials"},
		{map[string]string{"chat": "https://opencode.ai/v1?x=1"}, "query"},
		{map[string]string{"chat": "/v1"}, "not an absolute URL"},
		{map[string]string{"chatt": "https://opencode.ai/v1"}, "unknown endpoint"},
	} {
		cfg := base()
		cfg.Providers = []Provider{{Name: "p", BaseURL: "https://opencode.ai/zen/go/v1", BaseURLs: tc.urls}}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%v: %v", tc.urls, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%v: want %q, got %v", tc.urls, tc.err, err)
		}
	}
}

func TestProviderURL(t *testing.T) {
	cfg := base()
	cfg.Providers = []Provider{{
		Name: "p", BaseURL: "https://opencode.ai/zen/go/v1/",
		BaseURLs: map[string]string{"embeddings": "https://opencode.ai/inference/v1/"},
		Paths:    map[string]string{"embeddings": "/embed"},
	}}
	cfg.ApplyDefaults()
	p := cfg.Providers[0]
	for ep, want := range map[string]string{
		EndpointChat:       "https://opencode.ai/zen/go/v1/chat/completions",
		EndpointEmbeddings: "https://opencode.ai/inference/v1/embed",
		EndpointHealth:     "https://opencode.ai/zen/go/v1/models",
	} {
		if got := p.URL(ep); got != want {
			t.Errorf("%s: %s, want %s", ep, got, want)
		}
	}
}
