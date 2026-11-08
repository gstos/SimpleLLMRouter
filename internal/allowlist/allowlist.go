// Package allowlist restricts which client addresses may reach the router.
//
// Two layers share one compiled List: a net.Listener wrapper that drops
// disallowed TCP peers before any TLS handshake, and an HTTP middleware that
// resolves the real client behind trusted proxies (X-Forwarded-For) and answers
// 403. Loopback is always allowed. An empty allow list allows everyone.
package allowlist

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// List is a compiled allowlist. The zero value and nil allow everyone.
type List struct {
	allow   []netip.Prefix
	trusted []netip.Prefix
}

// Parse compiles allow_cidrs and trusted_proxies. Entries are CIDRs or bare IPs
// (a bare IP is a /32 or /128). All bad entries are reported together.
func Parse(allow, trusted []string) (*List, error) {
	var errs []string
	a := parseAll("server.allow_cidrs", allow, &errs)
	t := parseAll("server.trusted_proxies", trusted, &errs)
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return &List{allow: a, trusted: t}, nil
}

func parseAll(field string, in []string, errs *[]string) []netip.Prefix {
	var out []netip.Prefix
	for i, s := range in {
		p, err := parseEntry(s)
		if err != nil {
			*errs = append(*errs, fmt.Sprintf("%s[%d]: %q is not a CIDR or IP address", field, i, s))
			continue
		}
		out = append(out, p)
	}
	return out
}

func parseEntry(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		// An IPv4-mapped IPv6 prefix (::ffff:10.0.0.0/104) means the IPv4 range.
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked(), nil
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.WithZone("").Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func normalize(a netip.Addr) netip.Addr { return a.WithZone("").Unmap() }

func contains(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Active reports whether any filtering is configured.
func (l *List) Active() bool { return l != nil && len(l.allow) > 0 }

// Allowed reports whether a is loopback or listed in allow_cidrs (or the list
// is empty).
func (l *List) Allowed(a netip.Addr) bool {
	if !l.Active() {
		return true
	}
	if !a.IsValid() {
		return false
	}
	a = normalize(a)
	return a.IsLoopback() || contains(l.allow, a)
}

// Trusted reports whether a is a configured trusted proxy.
func (l *List) Trusted(a netip.Addr) bool {
	return l != nil && a.IsValid() && contains(l.trusted, normalize(a))
}

// PeerAllowed is the connection-level decision, before anything is read from
// the peer: loopback, allow_cidrs or trusted_proxies may connect. A trusted
// proxy is let through here and judged by its forwarded client per request.
func (l *List) PeerAllowed(a netip.Addr) bool {
	return l.Allowed(a) || l.Trusted(a)
}

// Client resolves the client address of a request from the TCP peer and the
// X-Forwarded-For values, and reports whether it may proceed. Without
// trusted_proxies the header is ignored. For a trusted peer the header is
// walked right to left, skipping trusted proxies; the first other entry is the
// client (the left side is attacker-controlled). A malformed entry is
// untrusted and invalid, so the request is denied (the returned address is
// then invalid).
func (l *List) Client(peer netip.Addr, xff []string) (client netip.Addr, ok bool) {
	if peer.IsValid() {
		peer = normalize(peer)
	}
	if !l.Active() {
		return peer, true
	}
	if !l.Trusted(peer) {
		return peer, l.Allowed(peer)
	}
	var entries []string
	for _, h := range xff {
		if strings.TrimSpace(h) == "" {
			continue
		}
		entries = append(entries, strings.Split(h, ",")...)
	}
	if len(entries) == 0 {
		return peer, l.Allowed(peer)
	}
	var last netip.Addr
	for i := len(entries) - 1; i >= 0; i-- {
		a, err := parseForwarded(entries[i])
		if err != nil {
			return netip.Addr{}, false
		}
		if l.Trusted(a) {
			last = a
			continue
		}
		return a, l.Allowed(a)
	}
	// Every hop was a trusted proxy: the chain started at the left-most one.
	return last, l.Allowed(last)
}

func parseForwarded(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return normalize(a), nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return normalize(ap.Addr()), nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if a, err := netip.ParseAddr(s[1 : len(s)-1]); err == nil {
			return normalize(a), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("bad address %q", s)
}

// AddrOf returns the IP of a connection address (invalid if it has none).
func AddrOf(a net.Addr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	if t, ok := a.(*net.TCPAddr); ok {
		ip, _ := netip.AddrFromSlice(t.IP)
		return normalize(ip)
	}
	return hostAddr(a.String())
}

func hostAddr(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return normalize(ap.Addr())
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return normalize(a)
	}
	return netip.Addr{}
}

// Guard holds the live List and enforces it on listeners and HTTP handlers.
// Set swaps the list atomically (config reload); readers see it per connection
// and per request.
type Guard struct {
	cur atomic.Pointer[List]
	log *slog.Logger

	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// LogInterval is the minimum time between log lines for the same rejected peer.
const LogInterval = time.Minute

// NewGuard returns a guard that allows everyone until Set is called.
func NewGuard(log *slog.Logger) *Guard {
	return &Guard{log: log, seen: map[string]time.Time{}, now: time.Now}
}

// Set installs a new list (nil allows everyone).
func (g *Guard) Set(l *List) { g.cur.Store(l) }

// List returns the current list (possibly nil).
func (g *Guard) List() *List { return g.cur.Load() }

// reject logs a denied peer at most once per peer per LogInterval.
func (g *Guard) reject(layer string, peer netip.Addr, client string) {
	key := peer.String() + "|" + client
	now := g.now()
	g.mu.Lock()
	if t, ok := g.seen[key]; ok && now.Sub(t) < LogInterval {
		g.mu.Unlock()
		return
	}
	if len(g.seen) > 1024 { // bound memory under a scan: drop expired entries
		for k, t := range g.seen {
			if now.Sub(t) >= LogInterval {
				delete(g.seen, k)
			}
		}
		if len(g.seen) > 1024 {
			g.seen = map[string]time.Time{}
		}
	}
	g.seen[key] = now
	g.mu.Unlock()
	if g.log != nil {
		g.log.Warn("client not in server.allow_cidrs; rejected (logged at most once per minute per address)",
			"layer", layer, "peer", peer.String(), "client", client)
	}
}

// Listener wraps ln: connections from disallowed peers are closed right after
// accept, before any TLS handshake, and Accept keeps going.
func (g *Guard) Listener(ln net.Listener) net.Listener { return &listener{Listener: ln, g: g} }

type listener struct {
	net.Listener
	g *Guard
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer := AddrOf(c.RemoteAddr())
		if l.g.List().PeerAllowed(peer) {
			return c, nil
		}
		_ = c.Close()
		l.g.reject("connection", peer, "")
	}
}

// Middleware calls deny for requests whose resolved client is not allowed.
// exempt, when set, lets matching requests through unchecked.
func (g *Guard) Middleware(next http.Handler, deny http.HandlerFunc, exempt func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := g.List()
		if !l.Active() || (exempt != nil && exempt(r)) {
			next.ServeHTTP(w, r)
			return
		}
		peer := hostAddr(r.RemoteAddr)
		client, ok := l.Client(peer, r.Header.Values("X-Forwarded-For"))
		if ok {
			next.ServeHTTP(w, r)
			return
		}
		cs := "(malformed X-Forwarded-For)"
		if client.IsValid() {
			cs = client.String()
		}
		g.reject("http", peer, cs)
		deny(w, r)
	})
}
