package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPassthroughTimesOutWaitingForUpstream(t *testing.T) {
	h, _, s := passServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	s.cur.Load().cfg.Server.RequestTimeout = 50 * time.Millisecond
	srv := httptest.NewServer(h)
	defer srv.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(srv.URL + "/provider/plain/models")
	if err != nil {
		t.Fatalf("passthrough did not enforce its own timeout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
}

func TestPassthroughTimesOutReadingSessionBody(t *testing.T) {
	h, seen, s := passServer(t, nil)
	s.cur.Load().cfg.Server.RequestTimeout = 50 * time.Millisecond
	srv := httptest.NewServer(h)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Send only part of the body and leave the connection open. The route must
	// not wait forever while buffering a conversation for session derivation.
	_, err = fmt.Fprint(conn, "POST /provider/oc/messages HTTP/1.1\r\nHost: router\r\nContent-Length: 10\r\n\r\nx")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("body read was not bounded by request_timeout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", resp.StatusCode)
	}
	if len(seen()) != 0 {
		t.Fatal("incomplete request reached upstream")
	}
}

func TestPassthroughTimeoutBoundsStreamingResponse(t *testing.T) {
	h, _, s := passServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	s.cur.Load().cfg.Server.RequestTimeout = 50 * time.Millisecond
	srv := httptest.NewServer(h)
	defer srv.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	start := time.Now()
	resp, err := client.Get(srv.URL + "/provider/plain/messages")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Once headers are sent, a timeout must terminate the stream rather than
	// attempting to replace its successful status with a JSON error response.
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "data: first") {
		t.Fatalf("first event missing: %q", body)
	}
	if time.Since(start) >= time.Second {
		t.Fatal("stream outlived the configured request timeout")
	}
}
