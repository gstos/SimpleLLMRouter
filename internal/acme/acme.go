// Package acme runs lego (https://go-acme.github.io/lego/) to obtain and renew
// the router's certificate in TLS mode "acme".
//
// The router only ever executes the lego binary, with arguments it builds from
// the structured config: no command, hook or LEGO_* variable comes from the
// config. lego runs with a minimal environment (PATH, HOME and the DNS
// provider's variables), so it never sees the router's own environment.
//
// `lego run` both issues and renews (only when due), so the runner simply calls
// it at startup and every CheckInterval, retrying failures with backoff. The
// certificate files it writes are picked up by the TLS manager like file mode.
package acme

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/config"
)

// MinMajor is the lego major version the router's arguments are written for.
const MinMajor = 5

// RunTimeout bounds one lego run (renewals may sleep a few minutes on purpose).
const RunTimeout = 20 * time.Minute

// Runner drives lego.
type Runner struct {
	Lego     string // lego binary (resolved path)
	Cfg      config.ACME
	LegoPath string // lego --path
	Webroot  string // HTTP-01 webroot (challenge http)
	CertName string
	Log      *slog.Logger
	// Env returns the DNS provider variables (decrypted). ok=false means they
	// aren't available yet (sealed router with encrypted values): wait.
	Env func() (env map[string]string, ok bool)
	// Issued is called after every successful run (the TLS manager reloads;
	// a no-op when nothing changed).
	Issued func()

	trigger chan struct{}
}

// LookPath finds lego and checks its version, returning the resolved path.
func LookPath(name string) (path, version string, err error) {
	if name == "" {
		name = "lego"
	}
	path, err = exec.LookPath(name)
	if err != nil {
		return "", "", fmt.Errorf("lego not found (%v): use the -acme container image, or install lego v%d (e.g. `brew install lego`) and make sure it is in PATH or set --lego", err, MinMajor)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return "", "", fmt.Errorf("running %s --version: %w", path, err)
	}
	m := regexp.MustCompile(`version v?(\d+)\.(\d+)\.(\d+)`).FindStringSubmatch(string(out))
	if m == nil {
		return "", "", fmt.Errorf("unrecognised lego version output: %q", strings.TrimSpace(string(out)))
	}
	version = fmt.Sprintf("v%s.%s.%s", m[1], m[2], m[3])
	if m[1] != fmt.Sprint(MinMajor) {
		return "", "", fmt.Errorf("lego %s found at %s; lego v%d.x is required", version, path, MinMajor)
	}
	return path, version, nil
}

// Trigger asks for a run now (e.g. after unseal or on SIGHUP).
func (r *Runner) Trigger() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// Start runs lego in the background until ctx is done.
func (r *Runner) Start(ctx context.Context) {
	r.trigger = make(chan struct{}, 1)
	go r.loop(ctx)
}

func (r *Runner) loop(ctx context.Context) {
	const minBackoff, maxBackoff = time.Minute, time.Hour
	backoff := minBackoff
	waitingLogged := false
	next := time.NewTimer(0) // first run right away
	defer next.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.trigger:
		case <-next.C:
		}

		env, ok := r.Env()
		if !ok {
			if !waitingLogged {
				r.Log.Info("acme: DNS credentials are encrypted; waiting for the router to be unsealed")
				waitingLogged = true
			}
			resetTimer(next, r.Cfg.CheckInterval)
			continue
		}
		waitingLogged = false

		if err := r.runOnce(ctx, env); err != nil {
			if ctx.Err() != nil {
				return
			}
			r.Log.Error("acme: lego failed; retrying", "in", backoff.String(), "err", err)
			resetTimer(next, backoff)
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = minBackoff
		r.Issued()
		resetTimer(next, r.Cfg.CheckInterval)
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// Args builds lego's arguments (exported for tests and diagnostics).
func (r *Runner) Args() []string {
	a := r.Cfg
	args := []string{
		"run",
		"--accept-tos",
		"--email", a.Email,
		"--server", a.Server,
		"--path", r.LegoPath,
		"--cert.name", r.CertName,
		"--key-type", a.KeyType,
		"--log.format", "json",
	}
	for _, d := range a.Domains {
		args = append(args, "--domains", d)
	}
	switch a.Challenge {
	case config.ChallengeHTTP:
		args = append(args, "--http", "--http.webroot", r.Webroot)
	case config.ChallengeDNS:
		args = append(args, "--dns", a.DNSProvider)
		for _, res := range a.DNSResolvers {
			args = append(args, "--dns.resolvers", res)
		}
		if a.DNSPropagationWait > 0 {
			args = append(args, "--dns.propagation.wait", a.DNSPropagationWait.String())
		}
	}
	return args
}

// environ builds lego's whole environment: nothing is inherited from the router.
func (r *Runner) environ(dnsEnv map[string]string) ([]string, error) {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + r.LegoPath,
	}
	if r.Cfg.CAFile != "" {
		env = append(env, "LEGO_CA_CERTIFICATES="+r.Cfg.CAFile)
	}
	for k, v := range dnsEnv {
		if err := config.CheckLegoEnvName(k); err != nil { // re-checked at the point of use
			return nil, err
		}
		env = append(env, k+"="+v)
	}
	return env, nil
}

func (r *Runner) runOnce(ctx context.Context, dnsEnv map[string]string) error {
	if err := os.MkdirAll(r.LegoPath, 0o700); err != nil {
		return err
	}
	if r.Cfg.Challenge == config.ChallengeHTTP {
		if err := os.MkdirAll(filepath.Join(r.Webroot, ".well-known", "acme-challenge"), 0o755); err != nil {
			return err
		}
	}
	env, err := r.environ(dnsEnv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, RunTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.Lego, r.Args()...)
	cmd.Env = env
	cmd.Dir = r.LegoPath
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	start := time.Now()
	r.Log.Info("acme: running lego", "domains", r.Cfg.Domains, "challenge", r.Cfg.Challenge, "server", r.Cfg.Server)
	err = cmd.Run()
	lastErr := r.relayLog(out.Bytes())
	if err != nil {
		if lastErr != "" {
			return fmt.Errorf("%w: %s", err, lastErr)
		}
		return err
	}
	r.Log.Info("acme: lego finished", "elapsed", time.Since(start).Round(time.Millisecond).String())
	return nil
}

// relayLog re-emits lego's JSON log lines through the router's logger and
// returns the last error message, if any.
func (r *Runner) relayLog(out []byte) (lastErr string) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		var rec map[string]any
		if json.Unmarshal(line, &rec) != nil {
			if s := strings.TrimSpace(string(line)); s != "" {
				r.Log.Info("lego", "output", truncate(s))
			}
			continue
		}
		msg, _ := rec["msg"].(string)
		level, _ := rec["level"].(string)
		attrs := []any{}
		for k, v := range rec {
			if k != "msg" && k != "level" && k != "time" {
				attrs = append(attrs, k, v)
			}
		}
		switch strings.ToUpper(level) {
		case "ERROR":
			if e, ok := rec["error"].(string); ok {
				lastErr = truncate(e)
			} else {
				lastErr = msg
			}
			r.Log.Error("lego: "+msg, attrs...)
		case "WARN", "WARNING":
			r.Log.Warn("lego: "+msg, attrs...)
		case "DEBUG":
			r.Log.Debug("lego: "+msg, attrs...)
		default:
			r.Log.Info("lego: "+msg, attrs...)
		}
	}
	return lastErr
}

func truncate(s string) string {
	if len(s) > 2000 {
		return s[:2000] + "..."
	}
	return s
}
