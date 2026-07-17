package proxy

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TargetHostHeader names the upstream host a client wants fetched. Passed
// per-request so tundler stays vendor-neutral: it never hardcodes whose pages
// are being fetched — the caller's deployment decides.
const TargetHostHeader = "X-Tundler-Target-Host"

// ImpersonateServer fetches upstream pages ON BEHALF OF a client, so the TLS
// that leaves this pod is originated here — in Go, with a real browser
// ClientHello (see ImpersonatingTransport) — rather than by the client.
//
// Why it exists: some edges fingerprint the TLS ClientHello (JA3/JA4) and
// blocklist non-browser signatures with 4xx regardless of exit IP or
// User-Agent. A client whose TLS stack can't reproduce a browser hello (e.g.
// a JVM: no GREASE, wrong extension order) cannot talk its way out — and
// reordering its ciphers only produces a NOVEL fingerprint, which such edges
// flag just as readily. The fix is for the client not to do the handshake at
// all: it asks us, and we fetch.
//
// Contract: the client sends an ordinary request to this server —
//
//	GET /<path> HTTP/1.1
//	X-Tundler-Target-Host: example.com
//
// and gets the upstream response relayed back.
//
// The UPSTREAM leg is always https — the scheme is hardcoded here, not taken
// from the caller, so no client can make this proxy fetch a target in the
// clear. That leg is the one that leaves the pod and the one the edge sees;
// it carries this pod's browser ClientHello.
//
// The CLIENT leg is plain HTTP by design: it never leaves the cluster, and it
// carries only whatever public page the caller asked for — no credentials. The
// operator's deployment decides whether that network is trusted.
//
// One browser profile per pod (PickProfile(podName)) — stable identity, and
// the fleet spreads across profiles because pods have distinct names. Runs
// alongside the CONNECT proxy during migration; it does NOT replace it until
// clients are switched over.
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
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// hopByHop headers must not be forwarded across the proxy boundary (RFC 7230).
var hopByHop = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
	"Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true,
	"Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

func (s *ImpersonateServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.Header.Get(TargetHostHeader))
	if host == "" {
		http.Error(w, TargetHostHeader+" is required (names the upstream host to fetch)",
			http.StatusBadRequest)
		return
	}
	// Defend the upstream leg from a malformed/hostile header: a value carrying
	// a scheme, path or port would otherwise be pasted straight into the URL.
	if strings.ContainsAny(host, "/\\ :") {
		http.Error(w, TargetHostHeader+" must be a bare host name", http.StatusBadRequest)
		return
	}

	target := url.URL{Scheme: "https", Host: host, Opaque: "", Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, "bad target: "+err.Error(), http.StatusBadRequest)
		return
	}
	copyHeaders(outReq.Header, r.Header)
	outReq.Header.Del(TargetHostHeader) // ours, not the upstream's
	outReq.Host = host

	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		// 502 is what a gateway owes its client when the upstream leg fails;
		// the caller's retry/backoff treats it like any transient tunnel error.
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
