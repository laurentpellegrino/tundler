package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// newTestTransport builds an ImpersonatingTransport that trusts self-signed
// httptest certs and dials directly.
func newTestTransport(hello utls.ClientHelloID) *ImpersonatingTransport {
	var d net.Dialer
	t := NewImpersonatingTransport(func(ctx context.Context, addr string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", addr)
	}, hello)
	t.insecure = true
	return t
}

// The whole point of phase 2 is that the impersonated upstream leg actually
// negotiates and speaks HTTP/2 (JA4 fidelity), returns the real response, and
// reuses one handshake for many requests. This exercises all three against a
// genuine h2 TLS server.
func TestImpersonatingTransport_H2RoundTripAndReuse(t *testing.T) {
	var hits int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		if r.ProtoMajor != 2 {
			t.Errorf("server saw proto %d, want HTTP/2", r.ProtoMajor)
		}
		w.Header().Set("X-Echo-Path", r.URL.Path)
		_, _ = io.WriteString(w, "pong")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	tr := newTestTransport(utls.HelloChrome_120)

	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/p", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("round trip %d: %v", i, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		if resp.ProtoMajor != 2 {
			t.Fatalf("client got proto %d, want HTTP/2 — impersonation must speak h2", resp.ProtoMajor)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "pong" || resp.Header.Get("X-Echo-Path") != "/p" {
			t.Fatalf("unexpected response body=%q path-hdr=%q", body, resp.Header.Get("X-Echo-Path"))
		}
	}
	if atomic.LoadInt64(&hits) != 3 {
		t.Fatalf("server saw %d hits, want 3", hits)
	}
	// All 3 requests must have multiplexed over ONE cached h2 conn.
	tr.mu.Lock()
	n := len(tr.conns)
	tr.mu.Unlock()
	if n != 1 {
		t.Fatalf("expected 1 pooled h2 conn for the host, got %d", n)
	}
	_ = http2.NextProtoTLS
}

// The forward-proxy handler must upgrade the upstream leg to TLS and relay the
// response, so the crawler can keep talking plain HTTP to a proxy.
func TestImpersonateServer_ForwardProxyUpgradesToTLS(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(207)
		_, _ = io.WriteString(w, "ok:"+r.URL.Path)
	}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	srv := NewImpersonateServer("", "tundler-tunnel-expressvpn-0", nil)
	srv.transport.insecure = true

	// Drive the handler directly (no listener needed): a forward-proxy request
	// carries the absolute target as http://<host>/path.
	proxied := httptest.NewServer(srv)
	defer proxied.Close()
	pu, _ := url.Parse(proxied.URL)

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := client.Get("http://" + bu.Host + "/xyz")
	if err != nil {
		t.Fatalf("proxied get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 207 || string(body) != "ok:/xyz" {
		t.Fatalf("got status=%d body=%q", resp.StatusCode, body)
	}
}

// A dialer returning (nil, nil) — the shape proxy.Server.DialUpstream uses to
// say "no custom dialer, fall back to a direct dial" — must surface as an
// error, never a panic. Regression: forwarding that nil conn straight to the
// TLS layer crashed every request through the handler in production.
func TestImpersonatingTransport_NilConnDoesNotPanic(t *testing.T) {
	tr := NewImpersonatingTransport(func(ctx context.Context, addr string) (net.Conn, error) {
		return nil, nil // no conn, no error
	}, utls.HelloChrome_120)
	req, _ := http.NewRequest(http.MethodGet, "https://example.invalid/x", nil)
	resp, err := tr.RoundTrip(req)
	if err == nil {
		t.Fatalf("want an error for a nil conn, got resp=%v", resp)
	}
}
