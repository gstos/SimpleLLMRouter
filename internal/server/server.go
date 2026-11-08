// Package server exposes an OpenRouter-compatible HTTP API and proxies requests
// to upstream providers with priority, round-robin, failover and sticky routing.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/allowlist"
	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/health"
	"github.com/gstos/SimpleLLMRouter/internal/router"
)

type Server struct {
	cur    atomic.Pointer[snapshot]
	client *http.Client
	log    *slog.Logger
	opts   Options
	guard  *allowlist.Guard
}

// Options configures optional server behaviour.
type Options struct {
	// Unseal receives a master key posted to /admin/unseal. It returns an error
	// wrapping ErrKeyRejected when the key is wrong. Nil disables the endpoint.
	Unseal func(ctx context.Context, masterKey string) error
	// Rotate re-encrypts everything under newKey (generated when empty) after
	// checking currentKey, and returns the new key. Errors wrapping
	// ErrKeyRejected mean currentKey was wrong. Nil disables the endpoint.
	Rotate func(ctx context.Context, currentKey, newKey string) (string, error)
	// TLSInfo, when set, describes the served certificate in /admin/health.
	TLSInfo func() any
	// AllowRemoteKeyAdmin accepts /admin/unseal and /admin/rotate-master-key from
	// non-loopback clients. Keys travel in the request body: only behind TLS.
	AllowRemoteKeyAdmin bool
}

// ErrKeyRejected marks an unseal attempt with a wrong or malformed master key.
var ErrKeyRejected = errors.New("master key rejected")

// snapshot is one loaded config. A request uses a single snapshot from start to
// end, so a reload never changes the rules under an in-flight request.
// A sealed snapshot (router == nil) has client keys but no decrypted credentials.
type snapshot struct {
	cfg     *config.Config
	keys    *auth.Store
	router  *router.Router
	checker *health.Checker
}

func (s *snapshot) sealed() bool { return s.router == nil }

// New returns a server with no config; call Update or Seal before serving.
func New(log *slog.Logger, opts Options) *Server {
	s := &Server{
		// No client-level timeout: streams can be long. The per-request context bounds it.
		client: &http.Client{
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("upstream redirects are not allowed")
			},
		},
		log:   log,
		opts:  opts,
		guard: allowlist.NewGuard(log),
	}
	s.Seal(&config.Config{})
	return s
}

// Update atomically switches to a new, decrypted config (startup, reload, unseal).
func (s *Server) Update(cfg *config.Config, rt *router.Router, checker *health.Checker) {
	s.setAllow(cfg)
	s.cur.Store(&snapshot{cfg: cfg, keys: auth.NewStore(cfg.APIKeys), router: rt, checker: checker})
}

// Seal serves cfg's client keys without credentials: API calls get 503 until a
// master key arrives via /admin/unseal.
func (s *Server) Seal(cfg *config.Config) {
	s.setAllow(cfg)
	s.cur.Store(&snapshot{cfg: cfg, keys: auth.NewStore(cfg.APIKeys)})
}

// setAllow compiles the client allowlist of cfg. A config that fails to parse
// was already rejected by Validate; keep the previous list rather than opening up.
func (s *Server) setAllow(cfg *config.Config) {
	l, err := allowlist.Parse(cfg.Server.AllowCIDRs, cfg.Server.TrustedProxies)
	if err != nil {
		s.log.Error("invalid server.allow_cidrs/trusted_proxies; keeping the previous list", "err", err)
		return
	}
	s.guard.Set(l)
}

// Guard returns the client allowlist guard, for wrapping listeners. It follows
// config reloads.
func (s *Server) Guard() *allowlist.Guard { return s.guard }

// Sealed reports whether the server is waiting for a master key.
func (s *Server) Sealed() bool { return s.cur.Load().sealed() }

// Handler returns the HTTP handler. Every API route is served under both
// /api/v1 (OpenRouter style) and /v1 (OpenAI style).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	chat := []string{config.TypeChat}
	for _, prefix := range []string{"/api/v1", "/v1"} {
		mux.HandleFunc("POST "+prefix+"/chat/completions", s.proxy(config.EndpointChat, chat))
		mux.HandleFunc("POST "+prefix+"/completions", s.proxy(config.EndpointCompletions, chat))
		mux.HandleFunc("POST "+prefix+"/embeddings", s.proxy(config.EndpointEmbeddings, []string{config.TypeEmbedding}))
		mux.HandleFunc("POST "+prefix+"/rerank", s.proxy(config.EndpointRerank, []string{config.TypeRerank}))
		mux.HandleFunc("GET "+prefix+"/models", s.models)
		// Anthropic Messages API: same routing, Anthropic error shape.
		messages := []string{config.TypeMessages}
		mux.Handle("POST "+prefix+"/messages", anthropicErrors(s.proxy(config.EndpointMessages, messages)))
		mux.Handle("POST "+prefix+"/messages/count_tokens", anthropicErrors(s.proxy(config.EndpointCountTokens, messages)))
	}
	mux.HandleFunc(ProviderPrefix, s.direct)
	mux.HandleFunc("GET /admin/health", s.adminHealth)
	mux.HandleFunc("POST /admin/unseal", s.unseal)
	mux.HandleFunc("POST /admin/rotate-master-key", s.rotate)
	// Liveness: 200 even while sealed (body "sealed"), so orchestrators don't
	// restart a router that is only waiting for its key.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if s.Sealed() {
			_, _ = io.WriteString(w, "sealed\n")
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	// The allowlist runs before routing, auth and every route (including /healthz;
	// loopback is always allowed).
	return s.guard.Middleware(mux, func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusForbidden, "client address not allowed")
	}, nil)
}

// authenticate returns the current snapshot and the caller's key, or writes a 401.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*snapshot, *auth.Key) {
	snap := s.cur.Load()
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		token = r.Header.Get("X-Api-Key")
	}
	k := snap.keys.Lookup(token)
	if k == nil {
		writeError(w, http.StatusUnauthorized, "invalid or missing API key")
	}
	return snap, k
}

// ready is authenticate plus a 503 while sealed.
func (s *Server) ready(w http.ResponseWriter, r *http.Request) (*snapshot, *auth.Key) {
	snap, key := s.authenticate(w, r)
	if key != nil && snap.sealed() {
		writeError(w, http.StatusServiceUnavailable, "router is sealed: waiting for the master key")
		return nil, nil
	}
	return snap, key
}

// unseal accepts the master key: {"master_key": "<base64>"}. Admin key required.
// It also applies a new key to an unsealed router (live master key rotation).
func (s *Server) unseal(w http.ResponseWriter, r *http.Request) {
	key, body := s.keyAdmin(w, r, s.opts.Unseal != nil)
	if key == nil {
		return
	}
	if err := s.opts.Unseal(r.Context(), body.MasterKey); err != nil {
		if errors.Is(err, ErrKeyRejected) {
			s.log.Warn("unseal rejected", "key", key.Name, "remote", r.RemoteAddr, "err", err)
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("unsealed", "key", key.Name, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"status": "unsealed"})
}

// rotate: {"master_key": "<current>", "new_master_key": "<optional>"} -> {"master_key": "<new>"}.
// The current key is required, so an admin client key alone can neither learn
// nor change the master key.
func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	key, body := s.keyAdmin(w, r, s.opts.Rotate != nil)
	if key == nil {
		return
	}
	if s.Sealed() {
		writeError(w, http.StatusServiceUnavailable, "router is sealed: unseal before rotating")
		return
	}
	newKey, err := s.opts.Rotate(r.Context(), body.MasterKey, body.NewMasterKey)
	if err != nil {
		if errors.Is(err, ErrKeyRejected) {
			s.log.Warn("master key rotation rejected", "key", key.Name, "remote", r.RemoteAddr, "err", err)
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		s.log.Error("master key rotation failed", "key", key.Name, "err", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("master key rotated", "key", key.Name, "remote", r.RemoteAddr)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"status": "rotated", "master_key": newKey})
}

type keyAdminBody struct {
	MasterKey    string `json:"master_key"`
	NewMasterKey string `json:"new_master_key"`
}

// keyAdmin applies the checks shared by the master key endpoints: enabled,
// localhost (unless allowed), admin client key, and a JSON body with master_key.
func (s *Server) keyAdmin(w http.ResponseWriter, r *http.Request, enabled bool) (*auth.Key, *keyAdminBody) {
	if !enabled {
		writeError(w, http.StatusNotFound, "endpoint disabled")
		return nil, nil
	}
	if !s.opts.AllowRemoteKeyAdmin && !isLoopback(r.RemoteAddr) {
		writeError(w, http.StatusForbidden, "only accepted from localhost (start serve with --allow-remote-key-admin, behind TLS)")
		return nil, nil
	}
	_, key := s.authenticate(w, r)
	if key == nil {
		return nil, nil
	}
	if !key.Admin {
		writeError(w, http.StatusForbidden, "admin key required")
		return nil, nil
	}
	var body keyAdminBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.MasterKey == "" {
		writeError(w, http.StatusBadRequest, `expected {"master_key": "..."}`)
		return nil, nil
	}
	return key, &body
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) proxy(endpoint string, types []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap, key := s.ready(w, r)
		if key == nil {
			return
		}

		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, snap.cfg.Server.MaxBodyBytes))
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large or unreadable")
			return
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(raw, &body); err != nil {
			writeError(w, http.StatusBadRequest, "request body must be a JSON object")
			return
		}
		var model string
		if err := json.Unmarshal(body["model"], &model); err != nil || model == "" {
			writeError(w, http.StatusBadRequest, "missing \"model\"")
			return
		}

		rt, ok := snap.router.Route(model)
		// A key may use an alias when its patterns match the alias or the model.
		if !ok || !(key.Allows(model) || key.Allows(rt.Name)) {
			// Same answer for unknown and forbidden so keys can't enumerate models.
			writeError(w, http.StatusNotFound, fmt.Sprintf("model %q not found", model))
			return
		}
		if !contains(types, rt.Type) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("model %q is a %s model and cannot be used on this endpoint", model, rt.Type))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), snap.cfg.Server.RequestTimeout)
		defer cancel()

		// The canonical name, so a conversation keeps its provider whichever
		// alias the client sends.
		sticky, conversation := stickyKey(key.Name, rt.Name, r, body)
		session := upstreamSession(sticky, conversation)
		plan := snap.router.Plan(rt, sticky)
		var lastErr string
		var lastResp *capturedResponse

		for i, t := range plan {
			body["model"], _ = json.Marshal(t.Model)
			payload, _ := json.Marshal(body)

			start := time.Now()
			resp, err := s.send(ctx, r, t, endpoint, payload, session)
			attempt := s.log.With("key", key.Name, "model", model, "target", t.ID, "attempt", i+1)

			if err != nil {
				if ctx.Err() != nil && r.Context().Err() != nil {
					attempt.Info("client went away")
					return
				}
				attempt.Warn("upstream error", "err", err, "elapsed", time.Since(start))
				snap.router.Failure(t)
				lastErr = err.Error()
				if ctx.Err() != nil {
					break // overall timeout: no time left for further attempts
				}
				continue
			}
			if retryable(resp.StatusCode) {
				cr := capture(resp)
				attempt.Warn("upstream failed, trying next", "status", resp.StatusCode, "elapsed", time.Since(start))
				snap.router.Failure(t)
				lastResp, lastErr = cr, fmt.Sprintf("upstream status %d", resp.StatusCode)
				continue
			}

			if resp.StatusCode < 300 {
				snap.router.Success(sticky, t)
			}
			attempt.Info("proxied", "status", resp.StatusCode, "elapsed", time.Since(start))
			s.relay(w, resp, t)
			return
		}

		if lastResp != nil {
			lastResp.write(w)
			return
		}
		writeError(w, http.StatusBadGateway, "all providers failed: "+lastErr)
	}
}

// forwardHeaders are client headers passed through to providers.
var forwardHeaders = []string{"Accept", "HTTP-Referer", "X-Title", "OpenAI-Organization", "Anthropic-Version", "Anthropic-Beta"}

// send makes one upstream attempt. session is the conversation id sent in the
// provider's session_header, if it has one.
func (s *Server) send(ctx context.Context, in *http.Request, t *router.Target, endpoint string, payload []byte, session string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Provider.BaseURL+t.Provider.Path(endpoint), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	for _, h := range forwardHeaders {
		if v := in.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	health.SetAuth(req, t.Provider)
	if h := t.Provider.SessionHeader; h != "" {
		if v := in.Header.Get(h); v != "" {
			session = v // the client's own id wins
		}
		req.Header.Set(h, session)
	}
	return s.client.Do(req)
}

var hopHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Transfer-Encoding": true, "Upgrade": true,
	"Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true, "Trailer": true,
	"Content-Length": true, "Set-Cookie": true,
}

// relay streams the upstream response to the client, flushing as data arrives (SSE).
func (s *Server) relay(w http.ResponseWriter, resp *http.Response, t *router.Target) {
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		if hopHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Router-Provider", t.Provider.Name)
	w.Header().Set("X-Router-Upstream-Model", t.Model)
	w.WriteHeader(resp.StatusCode)

	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.log.Warn("stream interrupted", "target", t.ID, "err", err)
			}
			return
		}
	}
}

// retryable reports whether a status should trigger failover to the next target.
// Client errors that would fail identically everywhere (400, 413, 422...) are returned as is.
func retryable(status int) bool {
	switch status {
	case 401, 402, 403, 404, 408, 409, 425, 429:
		return true
	}
	return status >= 500
}

// stickyKey identifies a "conversation" for cache affinity: client key + model +
// session. The session is X-Session-Id, else the "user" field, else a hash of the
// conversation prefix (through the first user message / prompt start), so distinct
// conversations still spread across equal-priority providers. conversation
// reports whether a session was found (embeddings and rerank usually have none).
func stickyKey(keyName, model string, r *http.Request, body map[string]json.RawMessage) (key string, conversation bool) {
	session := r.Header.Get("X-Session-Id")
	if session == "" {
		var user string
		if json.Unmarshal(body["user"], &user) == nil {
			session = user
		}
	}
	if session == "" {
		if msgs := body["messages"]; len(msgs) > 0 {
			var list []json.RawMessage
			if json.Unmarshal(msgs, &list) == nil {
				h := sha256.New()
				if sys := body["system"]; len(sys) > 0 { // Anthropic: system prompt outside messages
					h.Write(sys)
					h.Write([]byte{0})
				}
				for _, msg := range list {
					h.Write(msg)
					var message struct {
						Role string `json:"role"`
					}
					if json.Unmarshal(msg, &message) == nil && message.Role == "user" {
						break
					}
				}
				session = "p:" + hex.EncodeToString(h.Sum(nil)[:12])
			}
		} else if p := body["prompt"]; len(p) > 0 {
			h := sha256.Sum256(p[:min(len(p), 2048)])
			session = "p:" + hex.EncodeToString(h[:12])
		}
	}
	return keyName + "\x00" + model + "\x00" + session, session != ""
}

// upstreamSession is the id sent in a provider's session_header: a hash of the
// sticky key, so every turn of a conversation shares it while the client key
// name and the conversation content stay private. Requests that belong to no
// conversation get a random id.
func upstreamSession(sticky string, conversation bool) string {
	if !conversation {
		return health.RandomSession()
	}
	sum := sha256.Sum256([]byte(sticky))
	return hex.EncodeToString(sum[:16])
}

type modelEntry struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Type    string `json:"type"`
	OwnedBy string `json:"owned_by"`
}

func (s *Server) models(w http.ResponseWriter, r *http.Request) {
	snap, key := s.ready(w, r)
	if key == nil {
		return
	}
	data := []modelEntry{}
	for _, rt := range snap.router.Models() {
		for _, name := range append([]string{rt.Name}, rt.Aliases...) {
			if key.Allows(name) || key.Allows(rt.Name) {
				data = append(data, modelEntry{ID: name, Object: "model", Type: rt.Type, OwnedBy: "simple-router"})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

// adminHealth returns provider health. ?refresh=1 probes now instead of returning
// the last background results.
func (s *Server) adminHealth(w http.ResponseWriter, r *http.Request) {
	snap, key := s.authenticate(w, r)
	if key == nil {
		return
	}
	if !key.Admin {
		writeError(w, http.StatusForbidden, "admin key required")
		return
	}
	if snap.sealed() {
		writeError(w, http.StatusServiceUnavailable, "router is sealed: waiting for the master key")
		return
	}
	results := snap.checker.Last()
	if r.URL.Query().Get("refresh") != "" || len(results) == 0 {
		results = snap.checker.CheckAll(r.Context())
	}
	status := http.StatusOK
	for _, res := range results {
		if !res.Healthy {
			status = http.StatusServiceUnavailable
		}
	}
	out := map[string]any{"providers": results}
	if s.opts.TLSInfo != nil {
		if info := s.opts.TLSInfo(); info != nil {
			out["tls"] = info
		}
	}
	writeJSON(w, status, out)
}

// capturedResponse holds a failed upstream response so it can be returned if
// every target fails.
type capturedResponse struct {
	status int
	header http.Header
	body   []byte
}

func capture(resp *http.Response) *capturedResponse {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return &capturedResponse{status: resp.StatusCode, header: resp.Header, body: b}
}

func (c *capturedResponse) write(w http.ResponseWriter) {
	if ct := c.header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(c.status)
	_, _ = w.Write(c.body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError uses OpenRouter's error shape, or Anthropic's on /messages.
func writeError(w http.ResponseWriter, status int, msg string) {
	if _, ok := w.(*anthropicWriter); ok {
		writeJSON(w, status, map[string]any{"type": "error", "error": map[string]any{"type": anthropicErrorType(status), "message": msg}})
		return
	}
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": status, "message": msg}})
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
