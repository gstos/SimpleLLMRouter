package config

import (
	"strings"
	"testing"
)

func TestAllowCIDRsValidation(t *testing.T) {
	c := &Config{}
	c.Server.AllowCIDRs = []string{"10.0.0.0/8", "192.168.1.5", "fd00::/8"}
	c.Server.TrustedProxies = []string{"172.17.0.1"}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil && (strings.Contains(err.Error(), "allow_cidrs") || strings.Contains(err.Error(), "trusted_proxies")) {
		t.Fatalf("valid lists rejected: %v", err)
	}
	c.Server.AllowCIDRs = []string{"10.0.0.0/8", "bogus", "1.2.3.4/40"}
	c.Server.TrustedProxies = []string{"nope"}
	err := c.Validate()
	if err == nil {
		t.Fatal("bad entries accepted")
	}
	for _, want := range []string{"allow_cidrs[1]", "allow_cidrs[2]", "trusted_proxies[0]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q missing from %v", want, err)
		}
	}
}
