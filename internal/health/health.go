// Package health probes providers with a lightweight API call (GET /models by default).
package health

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/config"
)

// Result is the outcome of one provider probe.
type Result struct {
	Provider  string    `json:"provider"`
	Healthy   bool      `json:"healthy"`
	Status    int       `json:"status,omitempty"`
	LatencyMS int64     `json:"latency_ms"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Checker probes providers and remembers the latest results.
type Checker struct {
	providers []config.Provider
	client    *http.Client
	onResult  func(Result)

	mu   sync.RWMutex
	last map[string]Result
}

// New returns a Checker. onResult (optional) is called after every probe.
func New(providers []config.Provider, timeout time.Duration, onResult func(Result)) *Checker {
	// An auth: passthrough provider can't be probed: the client brings the
	// credentials.
	var probed []config.Provider
	for _, p := range providers {
		if p.Auth != config.AuthPassthrough {
			probed = append(probed, p)
		}
	}
	return &Checker{
		providers: probed,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("upstream redirects are not allowed")
			},
		},
		onResult: onResult,
		last:     map[string]Result{},
	}
}

// CheckAll probes every provider concurrently and returns results sorted by name.
func (c *Checker) CheckAll(ctx context.Context) []Result {
	results := make([]Result, len(c.providers))
	var wg sync.WaitGroup
	for i := range c.providers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = c.Check(ctx, &c.providers[i])
		}(i)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Provider < results[j].Provider })
	return results
}

// Check probes a single provider.
func (c *Checker) Check(ctx context.Context, p *config.Provider) Result {
	start := time.Now()
	res := Result{Provider: p.Name, CheckedAt: start}

	req, err := http.NewRequestWithContext(ctx, p.HealthMethod, p.URL(config.EndpointHealth), nil)
	if err == nil {
		// Anthropic's API requires a version header, even on /models; other
		// providers ignore it. A provider's own headers override it.
		req.Header.Set("Anthropic-Version", AnthropicVersion)
		SetAuth(req, p)
		if p.SessionHeader != "" {
			req.Header.Set(p.SessionHeader, RandomSession()) // no conversation to tie a probe to
		}
		var resp *http.Response
		resp, err = c.client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			res.Status = resp.StatusCode
			res.Healthy = resp.StatusCode >= 200 && resp.StatusCode < 300
			if !res.Healthy {
				res.Error = fmt.Sprintf("unexpected status %d", resp.StatusCode)
			}
		}
	}
	if err != nil {
		res.Error = err.Error()
	}
	res.LatencyMS = time.Since(start).Milliseconds()

	c.mu.Lock()
	c.last[p.Name] = res
	c.mu.Unlock()
	if c.onResult != nil {
		c.onResult(res)
	}
	return res
}

// Last returns the most recent results, sorted by provider name.
func (c *Checker) Last() []Result {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Result, 0, len(c.last))
	for _, r := range c.last {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

// Run probes all providers every interval until ctx is done.
func (c *Checker) Run(ctx context.Context, interval time.Duration) {
	c.CheckAll(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.CheckAll(ctx)
		}
	}
}

// SetAuth applies the provider's credentials and static headers to req.
func SetAuth(req *http.Request, p *config.Provider) {
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	if p.APIKey == "" {
		return
	}
	if p.AuthScheme == "none" {
		req.Header.Set(p.AuthHeader, p.APIKey)
	} else {
		req.Header.Set(p.AuthHeader, p.AuthScheme+" "+p.APIKey)
	}
}

// AnthropicVersion is sent on health probes (see Check), and on Messages API
// requests whose client did not send one.
const AnthropicVersion = "2023-06-01"

// RandomSession returns a random session id (32 hex chars) for requests that
// belong to no conversation.
func RandomSession() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
