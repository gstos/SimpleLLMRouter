package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gstos/SimpleLLMRouter/internal/config"
	"github.com/gstos/SimpleLLMRouter/internal/router"
)

func sessionFor(t *testing.T, keyName string, messages ...map[string]string) string {
	t.Helper()
	raw, err := json.Marshal(messages)
	if err != nil {
		t.Fatal(err)
	}
	return upstreamSession(stickyKey(keyName, "gpt", httptest.NewRequest("POST", "/", nil), map[string]json.RawMessage{"messages": raw}))
}

func TestUpstreamSessionStableAndPrivate(t *testing.T) {
	sys := map[string]string{"role": "system", "content": "Be helpful"}
	u1 := map[string]string{"role": "user", "content": "Hello"}
	first := sessionFor(t, "app", sys, u1)
	if len(first) != 32 {
		t.Fatalf("session %q is not 32 hex chars", first)
	}
	grown := sessionFor(t, "app", sys, u1, map[string]string{"role": "assistant", "content": "Hi"},
		map[string]string{"role": "user", "content": "More"})
	if grown != first {
		t.Fatal("session changed as the conversation grew")
	}
	if sessionFor(t, "app", sys, map[string]string{"role": "user", "content": "Other chat"}) == first {
		t.Fatal("different conversations share a session")
	}
	if sessionFor(t, "other-client", sys, u1) == first {
		t.Fatal("different client keys share a session")
	}
	// Nothing to tie the request to (embeddings, rerank): random each time.
	k, conv := stickyKey("app", "embed", httptest.NewRequest("POST", "/", nil), map[string]json.RawMessage{"input": json.RawMessage(`"x"`)})
	if conv || upstreamSession(k, conv) == upstreamSession(k, conv) {
		t.Fatal("requests without a conversation should get random sessions")
	}
}

func TestSendSessionHeader(t *testing.T) {
	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	defer up.Close()
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	send := func(p *config.Provider, in *http.Request) {
		t.Helper()
		resp, err := s.send(context.Background(), in, &router.Target{Provider: p}, config.EndpointChat, []byte(`{}`), "derived")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	send(&config.Provider{BaseURL: up.URL}, httptest.NewRequest("POST", "/", nil))
	if v := got.Get("X-Opencode-Session"); v != "" {
		t.Fatalf("header sent without session_header: %q", v)
	}

	p := &config.Provider{BaseURL: up.URL, SessionHeader: "x-opencode-session"} // viper may lowercase
	send(p, httptest.NewRequest("POST", "/", nil))
	if v := got.Get("X-Opencode-Session"); v != "derived" {
		t.Fatalf("session header = %q, want derived", v)
	}

	in := httptest.NewRequest("POST", "/", nil)
	in.Header.Set("X-Opencode-Session", "client-chosen")
	send(p, in)
	if v := got.Get("X-Opencode-Session"); v != "client-chosen" {
		t.Fatalf("client session not passed through: %q", v)
	}
}
