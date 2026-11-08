package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPassthroughRejectsKnownOversizedBodies(t *testing.T) {
	for _, tc := range []struct {
		name, provider, session string
	}{
		{"no session header configured", "plain", ""},
		{"generated session", "oc", ""},
		{"client session", "oc", "client-chosen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, seen, s := passServer(t, nil)
			s.cur.Load().cfg.Server.MaxBodyBytes = 16
			w := passDo(h, "POST", "/provider/"+tc.provider+"/messages", strings.Repeat("x", 17), "X-Opencode-Session", tc.session)
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413: %s", w.Code, w.Body.String())
			}
			if len(seen()) != 0 {
				t.Fatal("oversized request reached upstream")
			}
		})
	}
}

type limitProbeTransport struct {
	read int
}

func (p *limitProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b, err := io.ReadAll(r.Body)
	p.read = len(b)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

func TestPassthroughLimitsUnknownLengthWithClientSession(t *testing.T) {
	h, _, s := passServer(t, nil)
	s.cur.Load().cfg.Server.MaxBodyBytes = 16
	probe := &limitProbeTransport{}
	s.client.Transport = probe
	r := httptest.NewRequest("POST", "/provider/oc/messages", strings.NewReader(strings.Repeat("x", 17)))
	r.ContentLength = -1
	r.Header.Set("X-Opencode-Session", "client-chosen")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if probe.read > 16 {
		t.Fatalf("upstream read %d bytes, exceeding limit 16", probe.read)
	}
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %s", w.Code, w.Body.String())
	}
}
