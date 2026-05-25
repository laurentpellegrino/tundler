package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startServer boots a proxy on a free port, returns the addr and a
// cancel that stops it.
func startServer(t *testing.T, srv *Server) (string, context.CancelFunc) {
	t.Helper()
	// Bind to :0 first via a temp listener to grab a free port,
	// then close it and let proxy.Serve re-bind. Racy in theory,
	// fine for tests.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	srv.addr = addr

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	// Wait for the listener to actually be up before returning.
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return addr, cancel
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	t.Fatalf("proxy did not come up at %s", addr)
	return "", cancel
}

func TestConnect_TunnelsBytesAndInjectsHeaders(t *testing.T) {
	// Upstream HTTP server; client will tunnel a GET to it through
	// the proxy.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "ok")
		io.WriteString(w, "hello-from-upstream")
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	srv := New("placeholder", "tundler-pod-X", "10.0.0.5")
	srv.SetExitIP("203.0.113.7")
	addr, cancel := startServer(t, srv)
	defer cancel()

	// Open raw connection to proxy, send CONNECT, read response.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte("CONNECT " + upstreamHost + " HTTP/1.1\r\nHost: " + upstreamHost + "\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(conn)
	// Status line
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("expected 200, got: %s", strings.TrimSpace(line))
	}
	// Headers
	gotTunnelID := false
	gotNodeIP := false
	gotExitIP := false
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		h = strings.TrimSpace(h)
		if h == "" {
			break
		}
		switch {
		case strings.HasPrefix(strings.ToLower(h), "x-tundler-tunnel-id: tundler-pod-x"):
			gotTunnelID = true
		case strings.HasPrefix(strings.ToLower(h), "x-tundler-node-ip: 10.0.0.5"):
			gotNodeIP = true
		case strings.HasPrefix(strings.ToLower(h), "x-tundler-exit-ip: 203.0.113.7"):
			gotExitIP = true
		}
	}
	if !gotTunnelID || !gotNodeIP || !gotExitIP {
		t.Fatalf("missing headers: tunnelID=%v nodeIP=%v exitIP=%v", gotTunnelID, gotNodeIP, gotExitIP)
	}

	// Send HTTP request through the tunnel; expect upstream body.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + upstreamHost + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	body, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "hello-from-upstream") {
		t.Fatalf("upstream body missing: got %q", string(body))
	}

	// Stats sanity
	s := srv.Stats()
	if s.TotalConnect == 0 || s.TotalSuccess == 0 {
		t.Fatalf("stats not updated: %+v", s)
	}
}

func TestConnect_DrainingReturns503(t *testing.T) {
	srv := New("placeholder", "pod", "")
	srv.SetDraining(true)
	addr, cancel := startServer(t, srv)
	defer cancel()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	br := bufio.NewReader(conn)
	line, _ := br.ReadString('\n')
	if !strings.HasPrefix(line, "HTTP/1.1 503") {
		t.Fatalf("expected 503, got: %s", strings.TrimSpace(line))
	}
}

func TestConnect_BadRequest(t *testing.T) {
	srv := New("placeholder", "pod", "")
	addr, cancel := startServer(t, srv)
	defer cancel()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	// Send a GET instead of a CONNECT.
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	br := bufio.NewReader(conn)
	line, _ := br.ReadString('\n')
	if !strings.HasPrefix(line, "HTTP/1.1 400") {
		t.Fatalf("expected 400, got: %s", strings.TrimSpace(line))
	}
}

func TestSetExitIP_TakesEffectOnNextResponse(t *testing.T) {
	srv := New("placeholder", "pod", "")
	srv.SetExitIP("1.2.3.4")
	if got := srv.exitIP.Load().(string); got != "1.2.3.4" {
		t.Fatalf("exitIP not stored: %s", got)
	}
	srv.SetExitIP("5.6.7.8")
	if got := srv.exitIP.Load().(string); got != "5.6.7.8" {
		t.Fatalf("exitIP not updated: %s", got)
	}
	srv.SetExitIP("")
	if got := srv.exitIP.Load().(string); got != "" {
		t.Fatalf("exitIP not cleared: %s", got)
	}
}
