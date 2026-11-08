package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"

	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/configfile"
	"github.com/gstos/SimpleLLMRouter/internal/harden"
	"github.com/gstos/SimpleLLMRouter/internal/health"
	"github.com/gstos/SimpleLLMRouter/internal/router"
	"github.com/gstos/SimpleLLMRouter/internal/secrets"
	"github.com/gstos/SimpleLLMRouter/internal/server"
)

var (
	serveWatch          bool
	serveKeyStdin       bool
	serveRemoteKeyAdmin bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the router",
	Long: "Start the router.\n\n" +
		"Master key: from --master-key-file / SIMPLE_ROUTER_MASTER_KEY_FILE, SIMPLE_ROUTER_MASTER_KEY,\n" +
		"or --master-key-stdin (read once, kept only in memory). If none provides a key, the router\n" +
		"starts SEALED: API calls get 503 until the key is posted to /admin/unseal (admin client key\n" +
		"required, localhost only unless --allow-remote-key-admin), e.g. with `simple-router unseal`.\n" +
		"POST /admin/rotate-master-key (or `rotate master-key --api`) rotates the key live.\n" +
		"A key that is provided but wrong is a startup error.\n\n" +
		"Hot reload: on SIGHUP and (unless --watch=false) when the config or key file changes.\n" +
		"A config that fails to load, validate or decrypt is rejected and the running one stays.\n" +
		"Without a key file, reloads use the in-memory key. server.listen needs a restart.",
	RunE: func(cmd *cobra.Command, _ []string) error {
		log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		if h := harden.Apply(); len(h.Failed) > 0 {
			log.Warn("process hardening incomplete", "applied", h.Applied, "failed", fmt.Sprint(h.Failed))
		} else {
			log.Info("process hardened", "applied", h.Applied)
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		keys := &keyring{}
		if serveKeyStdin {
			k, err := readSecret(os.Stdin, "Master key: ")
			if err != nil {
				return fmt.Errorf("reading master key from stdin: %w", err)
			}
			ci, err := secrets.New(k)
			if err != nil {
				return err
			}
			keys.set(ci)
		}

		unsealReq := make(chan unsealRequest)
		rotateReq := make(chan rotateRequest)
		srv := server.New(log, server.Options{
			AllowRemoteKeyAdmin: serveRemoteKeyAdmin,
			Unseal: func(ctx context.Context, key string) error {
				req := unsealRequest{key: key, done: make(chan error, 1)}
				select {
				case unsealReq <- req:
				case <-ctx.Done():
					return ctx.Err()
				}
				return <-req.done
			},
			Rotate: func(ctx context.Context, current, newKey string) (string, error) {
				req := rotateRequest{current: current, newKey: newKey, done: make(chan rotateResult, 1)}
				select {
				case rotateReq <- req:
				case <-ctx.Done():
					return "", ctx.Err()
				}
				res := <-req.done
				return res.key, res.err
			},
		})

		var inst *instance // nil while sealed
		stopInst := func() {
			if inst != nil {
				inst.stop()
			}
		}

		// Startup: unsealed with a key, sealed without one, error on a bad key.
		ci, err := keys.resolve()
		var cfg *config.Config
		switch {
		case err == nil:
			if inst, err = loadInstance(ctx, ci, nil, log); err != nil {
				return err
			}
			cfg = inst.cfg
			srv.Update(inst.cfg, inst.router, inst.checker)
		case noKeyConfigured(err):
			if cfg, err = loadConfig(); err != nil {
				return err
			}
			srv.Seal(cfg)
		default:
			return err
		}
		listen := cfg.Server.Listen

		httpSrv := &http.Server{Addr: listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
		errc := make(chan error, 1)
		go func() { errc <- httpSrv.ListenAndServe() }()
		log.Info("listening", "addr", listen, "sealed", inst == nil, "providers", len(cfg.Providers), "models", len(cfg.Models), "watch", serveWatch)
		if inst == nil {
			log.Warn("SEALED: no master key provided; POST it to /admin/unseal (e.g. `simple-router unseal`)")
		}

		// activate decrypts the current config with ci and switches to it.
		activate := func(ci *secrets.Cipher, reason string) error {
			var prev *router.Router
			if inst != nil {
				prev = inst.router
			}
			next, err := loadInstance(ctx, ci, prev, log)
			if err != nil {
				return err
			}
			wasSealed := inst == nil
			keys.set(ci)
			srv.Update(next.cfg, next.router, next.checker)
			stopInst()
			inst = next
			if next.cfg.Server.Listen != listen {
				log.Warn("server.listen changed; restart to apply", "running", listen, "configured", next.cfg.Server.Listen)
			}
			if wasSealed && reason != "unseal" { // API unseals are logged by the server
				log.Info("unsealed", "reason", reason)
			}
			log.Info("config loaded", "reason", reason, "providers", len(next.cfg.Providers), "models", len(next.cfg.Models), "api_keys", len(next.cfg.APIKeys))
			return nil
		}

		reload := func(reason string) {
			ci, err := keys.resolve()
			if noKeyConfigured(err) && inst == nil {
				// Still sealed: pick up config changes (e.g. new admin keys) anyway.
				if cfg, err := loadConfig(); err != nil {
					log.Error("config reload failed", "reason", reason, "err", err)
				} else {
					srv.Seal(cfg)
					log.Info("config reloaded (still sealed)", "reason", reason)
				}
				return
			}
			if err == nil {
				err = activate(ci, reason)
			}
			if err != nil {
				log.Error("config reload failed; keeping the running config", "reason", reason, "err", err)
			}
		}

		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)

		var changed <-chan struct{}
		if serveWatch {
			if changed, err = watchFiles(ctx, watchedFiles(), log); err != nil {
				log.Warn("file watching unavailable; reload with SIGHUP", "err", err)
			}
		}

		for {
			select {
			case err := <-errc:
				stopInst()
				return err
			case <-hup:
				reload("SIGHUP")
			case <-changed:
				reload("file change")
			case req := <-unsealReq:
				req.done <- handleUnseal(req.key, activate)
			case req := <-rotateReq:
				key, err := handleRotate(req.current, req.newKey, keys, activate, log)
				req.done <- rotateResult{key, err}
			case <-ctx.Done():
				log.Info("shutting down")
				stopInst()
				shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := httpSrv.Shutdown(shutCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
					return err
				}
				return nil
			}
		}
	},
}

// handleUnseal applies a posted master key. A malformed key, one that doesn't
// match master_key_check, or one that can't decrypt the credentials is reported
// as server.ErrKeyRejected; other failures (e.g. a broken config) are not.
func handleUnseal(key string, activate func(*secrets.Cipher, string) error) error {
	ci, err := secrets.New(key)
	if err != nil {
		return fmt.Errorf("%w: %v", server.ErrKeyRejected, err)
	}
	err = activate(ci, "unseal")
	if errors.Is(err, config.ErrWrongMasterKey) || errors.Is(err, secrets.ErrDecrypt) {
		return fmt.Errorf("%w: %v", server.ErrKeyRejected, err)
	}
	return err
}

// handleRotate rotates the master key for a running router: verifies the current
// key against the config, re-encrypts and saves the config (replacing the key
// file too, if one is in use), then switches to the new key in memory.
func handleRotate(current, newKey string, keys *keyring, activate func(*secrets.Cipher, string) error, log *slog.Logger) (string, error) {
	curCi, err := secrets.New(current)
	if err != nil {
		return "", fmt.Errorf("%w: %v", server.ErrKeyRejected, err)
	}
	f, err := configfile.Load(v.GetString("config"))
	if err != nil {
		return "", err
	}
	if err := verifyCipher(f, curCi); err != nil {
		if errors.Is(err, config.ErrWrongMasterKey) {
			return "", fmt.Errorf("%w: %v", server.ErrKeyRejected, err)
		}
		return "", err
	}
	if newKey == "" {
		if newKey, err = secrets.GenerateKey(); err != nil {
			return "", err
		}
	}
	keyFile := v.GetString("master_key_file")
	if _, err := os.Stat(keyFile); keyFile == "" || err != nil {
		keyFile = "" // key lives only in memory: nothing to replace on disk
	}
	n, newCi, err := rotateMaster(f, curCi, newKey, keyFile, keyFile != "", func(msg string) { log.Warn("rotation: " + msg) })
	if err != nil {
		if newCi == nil {
			if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) {
				err = fmt.Errorf("can't replace key file %s (read-only mount, e.g. a Docker secret?); nothing changed. "+
					"Start the router without a key file (sealed + unseal) to rotate via the API: %w", keyFile, err)
			}
			return "", err // nothing changed
		}
		log.Error("master key rotation incomplete", "err", err)
	}
	keys.set(newCi)
	if err := activate(newCi, "master key rotation"); err != nil {
		return "", fmt.Errorf("config re-encrypted but reload failed: %w", err)
	}
	log.Info("master key rotated", "reencrypted", n, "key_file_updated", keyFile != "")
	return strings.TrimSpace(newKey), nil
}

type rotateRequest struct {
	current, newKey string
	done            chan rotateResult
}

type rotateResult struct {
	key string
	err error
}

type unsealRequest struct {
	key  string
	done chan error
}

// keyring holds the master key in memory. A configured key file stays
// authoritative (so a key file rotated by the CLI is picked up); otherwise the
// in-memory key is used (stdin, unseal, API rotation, flag/env read at startup).
type keyring struct {
	mu     sync.Mutex
	cipher *secrets.Cipher
}

func (k *keyring) set(ci *secrets.Cipher) {
	k.mu.Lock()
	k.cipher = ci
	k.mu.Unlock()
}

func (k *keyring) resolve() (*secrets.Cipher, error) {
	ci, err := masterCipher()
	if err == nil {
		if v.GetString("master_key") != "" {
			// --master-key / SIMPLE_ROUTER_MASTER_KEY are read once: later reloads use
			// the in-memory key, so an unseal or rotation isn't overridden by a stale
			// value. Also keeps the key out of anything we might spawn (though
			// /proc/1/environ and `docker inspect` still show the original value).
			v.Set("master_key", "")
			_ = os.Unsetenv("SIMPLE_ROUTER_MASTER_KEY")
		}
		k.set(ci)
		return ci, nil
	}
	if noKeyConfigured(err) {
		k.mu.Lock()
		defer k.mu.Unlock()
		if k.cipher != nil {
			return k.cipher, nil
		}
	}
	return nil, err
}

// instance is one loaded config with its router and running health checker.
type instance struct {
	cfg     *config.Config
	router  *router.Router
	checker *health.Checker
	stop    context.CancelFunc
}

// loadInstance reads the config, decrypts it with ci and starts its health
// checker. prev, when set, passes runtime routing state on to the new router.
func loadInstance(ctx context.Context, ci *secrets.Cipher, prev *router.Router, log *slog.Logger) (*instance, error) {
	cfg, err := loadDecryptedConfigWith(ci)
	if err != nil {
		return nil, err
	}
	rt := router.New(cfg, prev)
	checker := health.New(cfg.Providers, cfg.Server.HealthTimeout, func(r health.Result) {
		rt.SetProviderHealthy(r.Provider, r.Healthy)
		if !r.Healthy {
			log.Warn("provider unhealthy", "provider", r.Provider, "status", r.Status, "err", r.Error)
		}
	})
	cctx, cancel := context.WithCancel(ctx)
	if cfg.Server.HealthInterval > 0 {
		go checker.Run(cctx, cfg.Server.HealthInterval)
	}
	return &instance{cfg: cfg, router: rt, checker: checker, stop: cancel}, nil
}

func watchedFiles() []string {
	files := []string{v.GetString("config")}
	if v.GetString("master_key") == "" {
		if f := v.GetString("master_key_file"); f != "" {
			files = append(files, f)
		}
	}
	return files
}

// watchFiles signals when the content of any of files changes. It watches the
// parent directories, so atomic saves (write + rename) and Kubernetes ConfigMap
// symlink swaps are seen, then compares a content hash to drop no-op events.
// Events are debounced so a burst of writes causes a single reload.
func watchFiles(ctx context.Context, files []string, log *slog.Logger) (<-chan struct{}, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	dirs := map[string]bool{}
	for _, f := range files {
		dirs[filepath.Dir(f)] = true
	}
	watching := 0
	for d := range dirs {
		// A missing directory (e.g. no /run/secrets while sealed) must not stop
		// the config from being watched.
		if err := w.Add(d); err != nil {
			log.Warn("not watching directory", "dir", d, "err", err)
			continue
		}
		watching++
	}
	if watching == 0 {
		w.Close()
		return nil, errors.New("no watchable directory")
	}

	out := make(chan struct{}, 1)
	go func() {
		defer w.Close()
		last := hashFiles(files)
		var debounce <-chan time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				log.Warn("file watcher error", "err", err)
			case _, ok := <-w.Events:
				if !ok {
					return
				}
				debounce = time.After(300 * time.Millisecond)
			case <-debounce:
				debounce = nil
				if h := hashFiles(files); !bytes.Equal(h, last) {
					last = h
					select {
					case out <- struct{}{}:
					default: // a reload is already pending
					}
				}
			}
		}
	}()
	return out, nil
}

func hashFiles(files []string) []byte {
	h := sha256.New()
	for _, f := range files {
		b, _ := os.ReadFile(f) // a missing file hashes as empty; the reload then reports it
		h.Write([]byte(f))
		h.Write(b)
	}
	return h.Sum(nil)
}

func init() {
	f := serveCmd.Flags()
	f.BoolVar(&serveWatch, "watch", true, "reload automatically when the config or master key file changes")
	f.BoolVar(&serveKeyStdin, "master-key-stdin", false, "read the master key once from stdin (prompted on a terminal) and keep it only in memory")
	f.BoolVar(&serveRemoteKeyAdmin, "allow-remote-key-admin", false, "accept /admin/unseal and /admin/rotate-master-key from non-localhost clients (only behind TLS)")
}
