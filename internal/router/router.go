// Package router decides which upstream targets serve a request, and in what order.
//
// For each model, targets are grouped by priority (lowest first). Within a group the
// starting target rotates round robin. Targets that failed recently, or whose provider
// failed its health check, are moved to the end of the list (kept as a last resort).
// After a request succeeds on a target, the same sticky key (client + model + session)
// is pinned to that target for StickyTTL, so follow-up requests keep hitting a warm
// provider-side prompt cache, including after a failover.
package router

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gstos/SimpleLLMRouter/internal/config"
)

// Target is one upstream (provider + upstream model id) for a public model.
type Target struct {
	ID       string // "provider/model", unique within a route
	Provider *config.Provider
	Model    string
	Priority int
}

// Route holds the targets of one public model.
type Route struct {
	Name   string
	Type   string
	groups [][]*Target
	rr     []atomic.Uint64
	byID   map[string]*Target
}

type Router struct {
	routes   map[string]*Route
	names    []string
	sticky   *stickyStore
	cooldown time.Duration
	now      func() time.Time

	mu       sync.RWMutex
	failed   map[string]time.Time // target key -> unavailable until
	provDown map[string]bool      // provider -> failed last active health check
}

func New(cfg *config.Config) *Router {
	provs := map[string]*config.Provider{}
	for i := range cfg.Providers {
		provs[cfg.Providers[i].Name] = &cfg.Providers[i]
	}
	r := &Router{
		routes:   map[string]*Route{},
		sticky:   newStickyStore(cfg.Server.StickyTTL),
		cooldown: cfg.Server.FailureCooldown,
		now:      time.Now,
		failed:   map[string]time.Time{},
		provDown: map[string]bool{},
	}
	for _, m := range cfg.Models {
		rt := &Route{Name: m.Name, Type: m.Type, byID: map[string]*Target{}}
		byPrio := map[int][]*Target{}
		for _, t := range m.Targets {
			tg := &Target{ID: t.Provider + "/" + t.Model, Provider: provs[t.Provider], Model: t.Model, Priority: t.Priority}
			rt.byID[tg.ID] = tg
			byPrio[t.Priority] = append(byPrio[t.Priority], tg)
		}
		prios := make([]int, 0, len(byPrio))
		for p := range byPrio {
			prios = append(prios, p)
		}
		sort.Ints(prios)
		for _, p := range prios {
			rt.groups = append(rt.groups, byPrio[p])
		}
		rt.rr = make([]atomic.Uint64, len(rt.groups))
		r.routes[m.Name] = rt
		r.names = append(r.names, m.Name)
	}
	sort.Strings(r.names)
	return r
}

// Route returns the route for a public model name.
func (r *Router) Route(model string) (*Route, bool) {
	rt, ok := r.routes[model]
	return rt, ok
}

// Models returns all public model names, sorted.
func (r *Router) Models() []*Route {
	out := make([]*Route, 0, len(r.names))
	for _, n := range r.names {
		out = append(out, r.routes[n])
	}
	return out
}

// Plan returns targets in the order they should be attempted.
func (r *Router) Plan(rt *Route, stickyKey string) []*Target {
	ordered := make([]*Target, 0, len(rt.byID))
	for i, g := range rt.groups {
		start := int(rt.rr[i].Add(1)-1) % len(g)
		for j := range g {
			ordered = append(ordered, g[(start+j)%len(g)])
		}
	}

	if stickyKey != "" {
		if id, ok := r.sticky.get(stickyKey); ok {
			if t, ok := rt.byID[id]; ok {
				for i, o := range ordered {
					if o == t {
						copy(ordered[1:i+1], ordered[:i])
						ordered[0] = t
						break
					}
				}
			}
		}
	}

	// Stable partition: available targets first, unavailable ones as last resort.
	now := r.now()
	r.mu.RLock()
	avail := ordered[:0:0]
	var unavail []*Target
	for _, t := range ordered {
		if r.provDown[t.Provider.Name] || now.Before(r.failed[t.ID]) {
			unavail = append(unavail, t)
		} else {
			avail = append(avail, t)
		}
	}
	r.mu.RUnlock()
	return append(avail, unavail...)
}

// Success records that t served the request; the sticky key is pinned to it.
func (r *Router) Success(stickyKey string, t *Target) {
	r.mu.Lock()
	delete(r.failed, t.ID)
	r.mu.Unlock()
	if stickyKey != "" {
		r.sticky.set(stickyKey, t.ID)
	}
}

// Failure puts t on cooldown.
func (r *Router) Failure(t *Target) {
	r.mu.Lock()
	r.failed[t.ID] = r.now().Add(r.cooldown)
	r.mu.Unlock()
}

// SetProviderHealthy records the result of an active health check.
func (r *Router) SetProviderHealthy(provider string, healthy bool) {
	r.mu.Lock()
	if healthy {
		delete(r.provDown, provider)
	} else {
		r.provDown[provider] = true
	}
	r.mu.Unlock()
}

// stickyStore maps sticky keys to target IDs with a sliding TTL.
type stickyStore struct {
	ttl  time.Duration
	mu   sync.Mutex
	m    map[string]stickyEntry
	sets int
	now  func() time.Time
}

type stickyEntry struct {
	id      string
	expires time.Time
}

func newStickyStore(ttl time.Duration) *stickyStore {
	return &stickyStore{ttl: ttl, m: map[string]stickyEntry{}, now: time.Now}
}

func (s *stickyStore) get(key string) (string, bool) {
	if s.ttl <= 0 {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	if !ok || s.now().After(e.expires) {
		delete(s.m, key)
		return "", false
	}
	return e.id, true
}

func (s *stickyStore) set(key, id string) {
	if s.ttl <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.m[key] = stickyEntry{id: id, expires: now.Add(s.ttl)}
	s.sets++
	if s.sets%1024 == 0 { // amortized sweep of expired entries
		for k, e := range s.m {
			if now.After(e.expires) {
				delete(s.m, k)
			}
		}
	}
}
