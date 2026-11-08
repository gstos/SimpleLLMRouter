package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/health"
)

// PassPrefix is the passthrough route: /pass/<provider>/<path> is forwarded to
// <provider base_url>/<path>.
const PassPrefix = "/pass/"

// passthrough forwards a request unchanged to a provider marked passthrough:
// any method and path, streaming both ways. The client's own credentials go
// through untouched: the router neither checks them nor adds the provider's
// stored key, so no master key is needed (it works while sealed). There is no
// routing or failover: the target is the named provider. Only configured
// providers are reachable, never an arbitrary URL.
func (s *Server) passthrough(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, PassPrefix), "/")
	snap := s.cur.Load()
	p := snap.cfg.Provider(name)
	if p == nil || !p.Passthrough {
		writeError(w, http.StatusNotFound, "no passthrough provider "+strconv.Quote(name))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), snap.cfg.Server.RequestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	// Context cancellation bounds the upstream operation, but does not unblock
	// reads from an inbound HTTP body. Bound those reads on the connection too.
	rc := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	_ = rc.SetReadDeadline(deadline)
	defer func() {
		// Keep an expired deadline in place: net/http may still drain an
		// unfinished body after the handler returns.
		if time.Now().Before(deadline) {
			_ = rc.SetReadDeadline(time.Time{})
		}
	}()
	base, err := url.Parse(p.BaseURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "bad base_url")
		return
	}
	if r.ContentLength > snap.cfg.Server.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	// Apply the limit even when the client supplies its own session header.
	// Unknown-length bodies remain streamed, bounded by MaxBytesReader.
	r.Body = http.MaxBytesReader(w, r.Body, snap.cfg.Server.MaxBodyBytes)

	session := ""
	if h := p.SessionHeader; h != "" {
		session = r.Header.Get(h) // the client's own id wins
		if session == "" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				status := http.StatusBadRequest
				var tooBig *http.MaxBytesError
				if errors.As(err, &tooBig) {
					status = http.StatusRequestEntityTooLarge
				} else if isRequestTimeout(ctx, err) {
					status = http.StatusRequestTimeout
					w.Header().Set("Connection", "close")
				}
				writeError(w, status, err.Error())
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			session = passSession(p.Name, body)
		}
	}

	status := http.StatusBadGateway
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(base)
			// path.Clean on an absolute path drops any "..": the request can't
			// climb above base_url.
			pr.Out.URL.Path = strings.TrimSuffix(base.Path, "/") + path.Clean("/"+rest)
			pr.Out.URL.RawPath = ""
			pr.Out.Host = base.Host
			if session != "" {
				pr.Out.Header.Set(p.SessionHeader, session)
			}
			// No X-Forwarded-*: the client's address isn't passed on.
		},
		Transport:     s.client.Transport,
		FlushInterval: -1, // stream SSE as it arrives
		ModifyResponse: func(resp *http.Response) error {
			status = resp.StatusCode
			resp.Header.Set("X-Router-Provider", p.Name)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				status = http.StatusRequestEntityTooLarge
				writeError(w, status, "request body too large")
				return
			}
			s.log.Warn("passthrough upstream error", "provider", p.Name, "path", "/"+rest, "err", err)
			if isRequestTimeout(ctx, err) {
				status = http.StatusGatewayTimeout
				w.Header().Set("Connection", "close")
				writeError(w, status, "upstream request timed out")
				return
			}
			writeError(w, http.StatusBadGateway, "upstream error: "+err.Error())
		},
	}
	rp.ServeHTTP(w, r)
	s.log.Info("passthrough", "provider", p.Name, "method", r.Method, "path", "/"+rest,
		"status", status, "elapsed", time.Since(start).Round(time.Millisecond).String())
}

func isRequestTimeout(ctx context.Context, err error) bool {
	var timeout net.Error
	deadline, hasDeadline := ctx.Deadline()
	return errors.Is(ctx.Err(), context.DeadlineExceeded) ||
		(hasDeadline && !time.Now().Before(deadline)) ||
		(errors.As(err, &timeout) && timeout.Timeout())
}

// passSession derives the session id for a passthrough request from the
// conversation's stable prefix: the system prompt / instructions plus the
// messages up to and including the first user message (OpenAI chat, Anthropic
// messages, OpenAI responses). Every turn of a chat shares it; requests with no
// conversation get a random id.
func passSession(provider string, body []byte) string {
	var req struct {
		System       json.RawMessage   `json:"system"`       // Anthropic /messages
		Instructions json.RawMessage   `json:"instructions"` // OpenAI /responses
		Messages     []json.RawMessage `json:"messages"`     // chat completions, /messages
		Input        json.RawMessage   `json:"input"`        // OpenAI /responses
	}
	if json.Unmarshal(body, &req) != nil {
		return health.RandomSession()
	}
	items := req.Messages
	if len(items) == 0 && len(req.Input) > 0 {
		if req.Input[0] == '[' {
			_ = json.Unmarshal(req.Input, &items)
		} else {
			items = []json.RawMessage{req.Input} // a plain string input
		}
	}

	h := sha256.New()
	h.Write([]byte("pass\x00" + provider + "\x00"))
	seeded := false
	for _, part := range []json.RawMessage{req.System, req.Instructions} {
		if len(part) > 0 {
			h.Write(part)
			h.Write([]byte{0})
			seeded = true
		}
	}
	for _, item := range items {
		h.Write(item)
		h.Write([]byte{0})
		seeded = true
		var m struct {
			Role string `json:"role"`
		}
		if json.Unmarshal(item, &m) == nil && m.Role == "user" {
			break
		}
	}
	if !seeded {
		return health.RandomSession()
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}
