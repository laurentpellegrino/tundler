package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// dialFunc reaches a target host:port on the crawl egress' behalf — the same
// contract as the CONNECT proxy's DialFunc, so the impersonating transport
// routes through the VPN (or a proxy chain) exactly like the rest of the pod.
type dialFunc func(ctx context.Context, addr string) (net.Conn, error)

// ImpersonatingTransport is an http.RoundTripper that speaks to upstreams with
// a real browser's TLS ClientHello (via uTLS) and prefers HTTP/2 — matching
// what an edge sees from genuine Chrome/Firefox/Safari/Edge users, JA3 AND
// JA4. It is safe for concurrent use.
//
// Why not http.Transport/http2.Transport with a DialTLSContext hook: both
// type-assert the returned conn to crypto/tls's ConnectionState to validate
// ALPN, which a *utls.UConn does not satisfy (its ConnectionState is utls'
// own type). So we handshake ourselves, inspect the negotiated protocol
// directly, and hand the raw post-handshake conn to http2.NewClientConn —
// which frames h2 without re-checking ALPN.
//
// Connection reuse: one h2 ClientConn per host is cached and multiplexes every
// request for that host over a single handshake — so the ~100-300 ms VPN TLS
// cost is paid once, not per request. A dead conn is dropped and re-handshaked
// on the next call.
type ImpersonatingTransport struct {
	dial  dialFunc
	hello utls.ClientHelloID
	h2    *http2.Transport

	// insecure skips upstream cert verification — set ONLY by tests (against
	// self-signed httptest certs). Production leaves it false: impersonating a
	// browser is pointless if we don't also validate like one.
	insecure bool

	mu    sync.Mutex
	conns map[string]*http2.ClientConn // host -> reusable h2 conn
}

// NewImpersonatingTransport builds a transport that dials via dial and presents
// the given browser preset (see PickProfile).
func NewImpersonatingTransport(dial dialFunc, hello utls.ClientHelloID) *ImpersonatingTransport {
	return &ImpersonatingTransport{
		dial:  dial,
		hello: hello,
		h2:    &http2.Transport{},
		conns: make(map[string]*http2.ClientConn),
	}
}

// RoundTrip implements http.RoundTripper.
func (t *ImpersonatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	if host == "" {
		return nil, fmt.Errorf("impersonate: request URL has no host: %q", req.URL)
	}

	// Fast path: reuse a live cached h2 conn for this host.
	if cc := t.cachedH2(host); cc != nil {
		resp, err := cc.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		// Conn went bad (server closed it, GOAWAY, VPN rotated) — drop it
		// and fall through to a fresh handshake below.
		t.dropH2(host, cc)
	}

	addr := net.JoinHostPort(host, portOr(req.URL.Port(), "443"))
	raw, err := t.dial(req.Context(), addr)
	if err != nil {
		return nil, fmt.Errorf("impersonate: dial %s: %w", addr, err)
	}
	// A dialer that reports neither conn nor error is a caller bug (e.g.
	// forwarding proxy.Server.DialUpstream's ok=false nil conn). Handing nil
	// to the TLS layer panics the whole handler, so fail the request instead.
	if raw == nil {
		return nil, fmt.Errorf("impersonate: dialer returned no conn and no error for %s", addr)
	}
	uconn, err := HandshakeAs(req.Context(), raw,
		&utls.Config{ServerName: host, InsecureSkipVerify: t.insecure}, t.hello)
	if err != nil {
		return nil, fmt.Errorf("impersonate: tls handshake %s: %w", host, err)
	}

	switch uconn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS: // "h2"
		cc, err := t.h2.NewClientConn(uconn)
		if err != nil {
			_ = uconn.Close()
			return nil, fmt.Errorf("impersonate: h2 client conn %s: %w", host, err)
		}
		t.storeH2(host, cc)
		return cc.RoundTrip(req)
	default:
		// Server picked HTTP/1.1 (uncommon for modern edges). One-shot, no
		// pooling — correctness over throughput on this rare path.
		if err := req.Write(uconn); err != nil {
			_ = uconn.Close()
			return nil, fmt.Errorf("impersonate: h1 write %s: %w", host, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(uconn), req)
		if err != nil {
			_ = uconn.Close()
			return nil, fmt.Errorf("impersonate: h1 read %s: %w", host, err)
		}
		// Close the conn when the body is closed — no keep-alive for h1 here.
		resp.Body = &closingBody{ReadCloser: resp.Body, conn: uconn}
		return resp, nil
	}
}

func (t *ImpersonatingTransport) cachedH2(host string) *http2.ClientConn {
	t.mu.Lock()
	defer t.mu.Unlock()
	cc := t.conns[host]
	if cc != nil && cc.CanTakeNewRequest() {
		return cc
	}
	if cc != nil {
		delete(t.conns, host) // stale
	}
	return nil
}

func (t *ImpersonatingTransport) storeH2(host string, cc *http2.ClientConn) {
	t.mu.Lock()
	t.conns[host] = cc
	t.mu.Unlock()
}

func (t *ImpersonatingTransport) dropH2(host string, cc *http2.ClientConn) {
	t.mu.Lock()
	if t.conns[host] == cc {
		delete(t.conns, host)
	}
	t.mu.Unlock()
	_ = cc.Close()
}

func portOr(p, def string) string {
	if p == "" {
		return def
	}
	return p
}

// closingBody closes the underlying conn when the h1 response body is closed.
type closingBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *closingBody) Close() error {
	err := b.ReadCloser.Close()
	_ = b.conn.Close()
	return err
}
