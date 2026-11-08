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
	"net/http"
	"strings"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/auth"
	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/health"
	"github.com/gstos/SimpleLLMRouter/internal/router"
)

type Server struct {
	cfg     *config.Config
	keys    *auth.Store
	router  *router.Router
	checker *health.Checker
	client  *http.Client
	log     *slog.Logger
}

func New(cfg *config.Config, rt *router.Router, checker *health.Checker, log *slog.Logger) *Server {
	return &Server{
		cfg:     cfg,
		keys:    auth.NewStore(cfg.APIKeys),
		router:  rt,
		checker: checker,
		// No client-level timeout: streams can be long. The per-request context bounds it.
		client: &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()},
		log:    log,
	}
}

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
	}
	mux.HandleFunc("GET /admin/health", s.adminHealth)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) *auth.Key {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		token = r.Header.Get("X-Api-Key")
	}
	k := s.keys.Lookup(token)
	if k == nil {
		writeError(w, http.StatusUnauthorized, "invalid or missing API key")
	}
	return k
}

func (s *Server) proxy(endpoint string, types []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := s.authenticate(w, r)
		if key == nil {
			return
		}

		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.Server.MaxBodyBytes))
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

		rt, ok := s.router.Route(model)
		if !ok || !key.Allows(model) {
			// Same answer for unknown and forbidden so keys can't enumerate models.
			writeError(w, http.StatusNotFound, fmt.Sprintf("model %q not found", model))
			return
		}
		if !contains(types, rt.Type) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("model %q is a %s model and cannot be used on this endpoint", model, rt.Type))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Server.RequestTimeout)
		defer cancel()

		sticky := stickyKey(key.Name, model, r, body)
		plan := s.router.Plan(rt, sticky)
		var lastErr string
		var lastResp *capturedResponse

		for i, t := range plan {
			body["model"], _ = json.Marshal(t.Model)
			payload, _ := json.Marshal(body)

			start := time.Now()
			resp, err := s.send(ctx, r, t, endpoint, payload)
			attempt := s.log.With("key", key.Name, "model", model, "target", t.ID, "attempt", i+1)

			if err != nil {
				if ctx.Err() != nil && r.Context().Err() != nil {
					attempt.Info("client went away")
					return
				}
				attempt.Warn("upstream error", "err", err, "elapsed", time.Since(start))
				s.router.Failure(t)
				lastErr = err.Error()
				if ctx.Err() != nil {
					break // overall timeout: no time left for further attempts
				}
				continue
			}
			if retryable(resp.StatusCode) {
				cr := capture(resp)
				attempt.Warn("upstream failed, trying next", "status", resp.StatusCode, "elapsed", time.Since(start))
				s.router.Failure(t)
				lastResp, lastErr = cr, fmt.Sprintf("upstream status %d", resp.StatusCode)
				continue
			}

			if resp.StatusCode < 300 {
				s.router.Success(sticky, t)
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
var forwardHeaders = []string{"Accept", "HTTP-Referer", "X-Title", "OpenAI-Organization", "Anthropic-Version"}

func (s *Server) send(ctx context.Context, in *http.Request, t *router.Target, endpoint string, payload []byte) (*http.Response, error) {
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
// conversation prefix (first two messages / prompt start), so distinct
// conversations still spread across equal-priority providers.
func stickyKey(keyName, model string, r *http.Request, body map[string]json.RawMessage) string {
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
				for i := 0; i < len(list) && i < 2; i++ {
					h.Write(list[i])
				}
				session = "p:" + hex.EncodeToString(h.Sum(nil)[:12])
			}
		} else if p := body["prompt"]; len(p) > 0 {
			h := sha256.Sum256(p[:min(len(p), 2048)])
			session = "p:" + hex.EncodeToString(h[:12])
		}
	}
	return keyName + "\x00" + model + "\x00" + session
}

type modelEntry struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Type    string `json:"type"`
	OwnedBy string `json:"owned_by"`
}

func (s *Server) models(w http.ResponseWriter, r *http.Request) {
	key := s.authenticate(w, r)
	if key == nil {
		return
	}
	data := []modelEntry{}
	for _, rt := range s.router.Models() {
		if key.Allows(rt.Name) {
			data = append(data, modelEntry{ID: rt.Name, Object: "model", Type: rt.Type, OwnedBy: "simple-router"})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

// adminHealth returns provider health. ?refresh=1 probes now instead of returning
// the last background results.
func (s *Server) adminHealth(w http.ResponseWriter, r *http.Request) {
	key := s.authenticate(w, r)
	if key == nil {
		return
	}
	if !key.Admin {
		writeError(w, http.StatusForbidden, "admin key required")
		return
	}
	results := s.checker.Last()
	if r.URL.Query().Get("refresh") != "" || len(results) == 0 {
		results = s.checker.CheckAll(r.Context())
	}
	status := http.StatusOK
	for _, res := range results {
		if !res.Healthy {
			status = http.StatusServiceUnavailable
		}
	}
	writeJSON(w, status, map[string]any{"providers": results})
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

// writeError uses OpenRouter's error shape.
func writeError(w http.ResponseWriter, status int, msg string) {
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
