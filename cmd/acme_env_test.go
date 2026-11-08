package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gstos/SimpleLLMRouter/internal/configfile"
)

func TestRemoveEnvKeysAnyCase(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "server:\n  tls:\n    acme:\n      dns_env:\n        cloudflare_dns_api_token: a\n        CLOUDFLARE_DNS_API_TOKEN: b\n        AWS_REGION: c\n"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := configfile.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if n := removeEnvKeys(f, "CLOUDFLARE_DNS_API_TOKEN"); n != 2 {
		t.Fatalf("removed %d, want 2", n)
	}
	if kv := f.KeysIn(dnsEnvPath...); len(kv) != 1 || kv[0][0] != "AWS_REGION" {
		t.Fatalf("left %v", kv)
	}
}
