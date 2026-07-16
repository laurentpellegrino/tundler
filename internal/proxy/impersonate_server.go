package proxy

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ImpersonateServer is a plain-HTTP forward proxy that re-originates each
// request to its target over browser-impersonated TLS (uTLS + h2). A client
// points a normal HTTP proxy at it and requests http://<host>/<path>; the
// server upgrades the upstream leg to https with a real browser ClientHello,
// so the edge sees a genuine browser JA3/JA4 instead of the client's default
// TLS stack.
//
// One browser profile per pod (PickProfile(podName)) — stable identity, and
// the fleet spreads across profiles because pods have distinct names. This
// complements the CONNECT proxy on the other port; it does NOT replace it
// until clients are switched over.
type ImpersonateServer struct {
	addr      string
	transport *ImpersonatingTransport
	hello     utls.ClientHelloID
}

// NewImpersonateServer builds a server bound to addr. podName selects this
// pod's browser profile; dial routes upstream (nil = direct net dial, which in
// the tunnel pod egresses via the VPN default route).
func NewImpersonateServer(addr, podName string, dial dialFunc) *ImpersonateServer {
	if dial == nil {
		var d net.Dialer
		dial = func(ctx context.Context, target string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", target)
		}
	}
	hello := PickProfile(podName)
	return &ImpersonateServer{
		addr:      addr,
		transport: NewImpersonatingTransport(dial, hello),
		hello:     hello,
	}
}

// Profile reports the browser preset this pod presents (for logging/metrics).
func (s *ImpersonateServer) Profile() string { return s.hello.Str() }

// Serve runs until ctx is cancelled.
func (s *ImpersonateServer) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	log.Printf("impersonate-proxy: listening on %s as %s", s.addr, s.hello.Str())
	return srv.ListenAndServe()
}

// hopByHop headers must not be forwarded across the proxy boundary (RFC 7230).
var hopByHop = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
	"Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true,
	"Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

func (s *ImpersonateServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Forward-proxy requests carry an absolute-form URL (GET http://host/path).
	// CONNECT is handled by the other proxy; reject it here to avoid confusion.
	if r.Method == http.MethodConnect || !r.URL.IsAbs() {
		http.Error(w, "impersonate-proxy expects absolute-form forward-proxy requests", http.StatusBadRequest)
		return
	}

	target := *r.URL
	target.Scheme = "https" // always upgrade the upstream leg to TLS
	if target.Host == "" {
		target.Host = r.Host
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, "bad target: "+err.Error(), http.StatusBadRequest)
		return
	}
	copyHeaders(outReq.Header, r.Header)
	outReq.Host = target.Hostname()

	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		// 502 mirrors what a forward proxy returns when the upstream leg fails;
		// the crawler's retry/AIMD treats it like any transient tunnel error.
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
