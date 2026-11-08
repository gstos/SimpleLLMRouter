package allowlist

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func mustList(t *testing.T, allow, trusted []string) *List {
	t.Helper()
	l, err := Parse(allow, trusted)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestParseErrors(t *testing.T) {
	_, err := Parse([]string{"10.0.0.0/8", "nope", "10.0.0.0/33"}, []string{"1.2.3"})
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"allow_cidrs[1]", "allow_cidrs[2]", "trusted_proxies[0]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestAllowed(t *testing.T) {
	l := mustList(t, []string{"10.0.0.0/8", "192.168.1.7", "2001:db8::/32", "fd00::1"}, nil)
	cases := []struct {
		addr string
		want bool
	}{
		{"10.1.2.3", true},
		{"11.0.0.1", false},
		{"192.168.1.7", true},
		{"192.168.1.8", false},
		{"2001:db8::5", true},
		{"2001:db9::5", false},
		{"fd00::1", true},
		{"fd00::2", false},
		{"::ffff:10.0.0.5", true}, // IPv4-mapped is unmapped
		{"::ffff:11.0.0.5", false},
		{"127.0.0.1", true}, // loopback always
		{"127.9.9.9", true},
		{"::1", true},
		{"::ffff:127.0.0.1", true},
	}
	for _, c := range cases {
		if got := l.Allowed(ip(c.addr)); got != c.want {
			t.Errorf("Allowed(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
	if l.Allowed(netip.Addr{}) {
		t.Error("invalid address allowed")
	}
}

func TestEmptyAllowsAll(t *testing.T) {
	for _, l := range []*List{nil, {}, mustList(t, nil, []string{"10.0.0.1"})} {
		if !l.Allowed(ip("8.8.8.8")) || !l.PeerAllowed(ip("8.8.8.8")) {
			t.Error("empty list must allow all")
		}
		if c, ok := l.Client(ip("8.8.8.8"), []string{"1.1.1.1"}); !ok || c != ip("8.8.8.8") {
			t.Errorf("Client = %v %v", c, ok)
		}
	}
}

func TestMappedPrefix(t *testing.T) {
	l := mustList(t, []string{"::ffff:10.0.0.0/104"}, nil)
	if !l.Allowed(ip("10.9.9.9")) || l.Allowed(ip("11.0.0.1")) {
		t.Error("mapped prefix not unmapped")
	}
}

func TestClientXFF(t *testing.T) {
	l := mustList(t, []string{"192.168.0.0/16"}, []string{"10.0.0.1", "10.0.0.2"})
	cases := []struct {
		name   string
		peer   string
		xff    []string
		client string // "" = invalid
		ok     bool
	}{
		{"untrusted peer ignores xff", "8.8.8.8", []string{"192.168.1.1"}, "8.8.8.8", false},
		{"untrusted allowed peer", "192.168.1.5", []string{"8.8.8.8"}, "192.168.1.5", true},
		{"trusted, no header", "10.0.0.1", nil, "10.0.0.1", false}, // proxy itself is not in allow_cidrs
		{"trusted, empty header", "10.0.0.1", []string{" "}, "10.0.0.1", false},
		{"trusted, allowed client", "10.0.0.1", []string{"192.168.3.4"}, "192.168.3.4", true},
		{"trusted, denied client", "10.0.0.1", []string{"8.8.8.8"}, "8.8.8.8", false},
		{"spoofed left entry", "10.0.0.1", []string{"192.168.3.4, 8.8.8.8"}, "8.8.8.8", false},
		{"spoofed left entry, 2 headers", "10.0.0.1", []string{"192.168.3.4", "8.8.8.8"}, "8.8.8.8", false},
		{"chain of trusted proxies", "10.0.0.1", []string{"8.8.8.8, 192.168.3.4, 10.0.0.2"}, "192.168.3.4", true},
		{"chain, spoof before real", "10.0.0.1", []string{"192.168.1.1, 8.8.8.8, 10.0.0.2"}, "8.8.8.8", false},
		{"all trusted", "10.0.0.1", []string{"10.0.0.2"}, "10.0.0.2", false},
		{"garbage", "10.0.0.1", []string{"192.168.3.4, banana"}, "", false},
		{"garbage left of real", "10.0.0.1", []string{"banana, 192.168.3.4"}, "192.168.3.4", true},
		{"empty entry", "10.0.0.1", []string{"192.168.3.4,"}, "", false},
		{"port and brackets", "10.0.0.1", []string{"[::ffff:192.168.9.9]:1234"}, "192.168.9.9", true},
		{"bracketed v6 no port", "10.0.0.1", []string{"[2001:db8::1]"}, "2001:db8::1", false},
		{"mapped peer", "::ffff:10.0.0.1", []string{"192.168.3.4"}, "192.168.3.4", true},
		{"loopback client", "10.0.0.1", []string{"127.0.0.1"}, "127.0.0.1", true},
	}
	for _, c := range cases {
		got, ok := l.Client(ip(c.peer), c.xff)
		want := netip.Addr{}
		if c.client != "" {
			want = ip(c.client)
		}
		if got != want || ok != c.ok {
			t.Errorf("%s: Client = %v,%v want %v,%v", c.name, got, ok, want, c.ok)
		}
	}
}

func TestPeerAllowed(t *testing.T) {
	l := mustList(t, []string{"192.168.0.0/16"}, []string{"10.0.0.1"})
	for addr, want := range map[string]bool{"192.168.1.1": true, "10.0.0.1": true, "127.0.0.1": true, "8.8.8.8": false, "10.0.0.2": false} {
		if got := l.PeerAllowed(ip(addr)); got != want {
			t.Errorf("PeerAllowed(%s) = %v", addr, got)
		}
	}
}

type fakeConn struct {
	net.Conn
	remote net.Addr
	closed chan struct{}
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeConn) Close() error         { close(c.closed); return nil }

type fakeListener struct {
	net.Listener
	conns chan net.Conn
}

func (f *fakeListener) Accept() (net.Conn, error) {
	c, ok := <-f.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func TestListenerDropsDisallowedAndKeepsAccepting(t *testing.T) {
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.Set(mustList(t, []string{"192.168.0.0/16"}, []string{"10.0.0.1"}))
	fl := &fakeListener{conns: make(chan net.Conn, 8)}
	mk := func(a string) *fakeConn {
		return &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP(a), Port: 5000}, closed: make(chan struct{})}
	}
	bad1, bad2, good, proxy := mk("8.8.8.8"), mk("1.1.1.1"), mk("192.168.4.4"), mk("10.0.0.1")
	for _, c := range []*fakeConn{bad1, bad2, good, proxy} {
		fl.conns <- c
	}
	ln := g.Listener(fl)
	for _, want := range []*fakeConn{good, proxy} {
		c, err := ln.Accept()
		if err != nil || c != net.Conn(want) {
			t.Fatalf("Accept = %v, %v", c, err)
		}
	}
	for _, c := range []*fakeConn{bad1, bad2} {
		select {
		case <-c.closed:
		default:
			t.Errorf("%v not closed", c.remote)
		}
	}
	select {
	case <-good.closed:
		t.Error("allowed conn closed")
	default:
	}
	// Live swap: now everything is allowed.
	g.Set(nil)
	late := mk("8.8.4.4")
	fl.conns <- late
	if c, _ := ln.Accept(); c != net.Conn(late) {
		t.Error("swap not applied")
	}
	close(fl.conns)
	if _, err := ln.Accept(); err == nil {
		t.Error("want accept error to propagate")
	}
}

func TestListenerRealTCPLoopback(t *testing.T) {
	g := NewGuard(nil)
	g.Set(mustList(t, []string{"203.0.113.0/24"}, nil)) // excludes everything but loopback
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hi") })}
	go srv.Serve(g.Listener(raw))
	defer srv.Close()
	resp, err := http.Get("http://" + raw.Addr().String())
	if err != nil {
		t.Fatalf("loopback must always connect: %v", err)
	}
	resp.Body.Close()
}

func TestMiddleware(t *testing.T) {
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.Set(mustList(t, []string{"192.168.0.0/16"}, []string{"10.0.0.1"}))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	deny := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }
	h := g.Middleware(next, deny, func(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/ok/") })
	do := func(remote, path, xff string) int {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for _, c := range []struct {
		remote, path, xff string
		want              int
	}{
		{"8.8.8.8:1", "/x", "", 403},
		{"8.8.8.8:1", "/x", "192.168.1.1", 403}, // xff ignored from untrusted peer
		{"8.8.8.8:1", "/ok/tok", "", 204},       // exempt path
		{"8.8.8.8:1", "/okay", "", 403},
		{"192.168.1.1:1", "/x", "", 204},
		{"127.0.0.1:1", "/x", "", 204},
		{"[::1]:1", "/x", "", 204},
		{"10.0.0.1:1", "/x", "192.168.2.2", 204},
		{"10.0.0.1:1", "/x", "192.168.2.2, 8.8.8.8", 403},
		{"10.0.0.1:1", "/x", "garbage", 403},
	} {
		if got := do(c.remote, c.path, c.xff); got != c.want {
			t.Errorf("%s %s xff=%q: %d want %d", c.remote, c.path, c.xff, got, c.want)
		}
	}
}

func TestRejectLogRateLimited(t *testing.T) {
	var sb strings.Builder
	g := NewGuard(slog.New(slog.NewTextHandler(&sb, nil)))
	now := time.Unix(1000, 0)
	g.now = func() time.Time { return now }
	for i := 0; i < 100; i++ {
		g.reject("connection", ip("8.8.8.8"), "")
	}
	if n := strings.Count(sb.String(), "rejected"); n != 1 {
		t.Fatalf("logged %d lines for one peer", n)
	}
	g.reject("connection", ip("8.8.4.4"), "")
	now = now.Add(LogInterval + time.Second)
	g.reject("connection", ip("8.8.8.8"), "")
	if n := strings.Count(sb.String(), "rejected"); n != 3 {
		t.Fatalf("logged %d lines, want 3", n)
	}
}
