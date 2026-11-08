package acme

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/config"
)

func runner(a config.ACME) *Runner {
	return &Runner{Cfg: a, LegoPath: "/data/lego", Webroot: "/data/webroot", CertName: "simple-router",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestArgs(t *testing.T) {
	r := runner(config.ACME{Email: "a@b.c", Domains: []string{"x.test", "*.x.test"}, Server: "letsencrypt-staging",
		KeyType: "EC256", Challenge: config.ChallengeDNS, DNSProvider: "cloudflare",
		DNSResolvers: []string{"1.1.1.1:53"}, DNSPropagationWait: 30 * time.Second})
	got := strings.Join(r.Args(), " ")
	for _, want := range []string{"run --accept-tos", "--email a@b.c", "--server letsencrypt-staging", "--path /data/lego",
		"--cert.name simple-router", "--domains x.test --domains *.x.test", "--dns cloudflare",
		"--dns.resolvers 1.1.1.1:53", "--dns.propagation.wait 30s", "--log.format json"} {
		if !strings.Contains(got, want) {
			t.Errorf("args %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "hook") {
		t.Errorf("hook in args: %s", got)
	}

	r = runner(config.ACME{Email: "a@b.c", Domains: []string{"x.test"}, KeyType: "EC256", Challenge: config.ChallengeHTTP})
	if got := strings.Join(r.Args(), " "); !strings.Contains(got, "--http --http.webroot /data/webroot") || strings.Contains(got, "--dns") {
		t.Errorf("http args: %s", got)
	}
}

func TestEnvironIsMinimalAndGuarded(t *testing.T) {
	t.Setenv("SIMPLE_ROUTER_MASTER_KEY", "must-not-leak")
	r := runner(config.ACME{CAFile: "/ca.pem"})
	env, err := r.environ(map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "tok"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{"HOME=/data/lego", "LEGO_CA_CERTIFICATES=/ca.pem", "CLOUDFLARE_DNS_API_TOKEN=tok"} {
		if !slices.Contains(env, want) {
			t.Errorf("env missing %s: %v", want, env)
		}
	}
	if strings.Contains(joined, "must-not-leak") {
		t.Fatal("router environment leaked into lego")
	}
	for _, bad := range []string{"LEGO_DEPLOY_HOOK", "LD_PRELOAD", "PATH", "lower_case"} {
		if _, err := r.environ(map[string]string{bad: "x"}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestLookPathVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	dir := t.TempDir()
	write := func(name, out string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho '"+out+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, v, err := LookPath(write("lego5", "lego version v5.6.0 linux/amd64")); err != nil || v != "v5.6.0" {
		t.Fatalf("v5: %v %v", v, err)
	}
	if _, _, err := LookPath(write("lego4", "lego version 4.35.2 linux/amd64")); err == nil || !strings.Contains(err.Error(), "v5.x is required") {
		t.Fatalf("v4 accepted: %v", err)
	}
	if _, _, err := LookPath(filepath.Join(dir, "missing")); err == nil || !strings.Contains(err.Error(), "-acme container image") {
		t.Fatalf("missing: %v", err)
	}
}

func TestRunOnceResolvesPathsBeforeChangingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	// This stand-in records exactly what lego sees, without contacting a CA.
	script := "#!/bin/sh\npwd > cwd.txt\nprintf '%s\\n' \"$@\" > args.txt\nprintf '%s\\n' \"$LEGO_CA_CERTIFICATES\" > ca.txt\n"
	if err := os.WriteFile("lego", []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &Runner{
		Lego: "./lego", LegoPath: "tls/lego", Webroot: "tls/webroot",
		Cfg: config.ACME{Challenge: config.ChallengeHTTP, CAFile: "ca.pem"},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := r.runOnce(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join("tls", "lego", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	if got, want := read("cwd.txt"), filepath.Join(dir, "tls", "lego"); got != want {
		t.Fatalf("cwd = %q, want %q", got, want)
	}
	args := read("args.txt")
	for _, want := range []string{"--path\n" + filepath.Join(dir, "tls", "lego"), "--http.webroot\n" + filepath.Join(dir, "tls", "webroot")} {
		if !strings.Contains(args, want) {
			t.Errorf("arguments %q missing %q", args, want)
		}
	}
	if got, want := read("ca.txt"), filepath.Join(dir, "ca.pem"); got != want {
		t.Errorf("CA file = %q, want %q", got, want)
	}
	if r.LegoPath != "tls/lego" {
		t.Error("runOnce modified runner configuration")
	}
}
