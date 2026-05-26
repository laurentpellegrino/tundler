// Package proxy is a minimal HTTP CONNECT forward-proxy embedded in
// the tundler-tunnel binary. Replaces the sibling envoy container in
// the per-pod VPN-hub architecture: clients (crawlers) CONNECT to
// this proxy, which dials the upstream target via the pod's
// default route (VPN tun0 by virtue of tundler-tunnel managing the
// VPN client) and tunnels bytes bidirectionally.
//
// Why not envoy: envoy was sub-optimally coupled to tundler-tunnel
// via xDS, with two-container probe races, the %ENV() bootstrap
// pitfall, Lua-filter file IO per response, and occasional multi-
// minute unresponsiveness that fired liveness probes. By putting
// the proxy in the same Go binary that manages the VPN, we
// eliminate all inter-container coordination and shrink the pod to
// one container.
//
// Scope: HTTP/1.1 CONNECT only. The pre-existing envoy config also
// supported plain HTTP forward-proxy (`prefix: /`) but the crawler
// never uses that path — every upstream is HTTPS, so it always
// CONNECTs. If a future need arises for plain HTTP, add an
// alternate handler branch.
//
// Concurrency: each accepted connection is handled in its own
// goroutine. The hot path (after CONNECT parse + upstream dial) is
// just two io.Copy goroutines per connection — Go's scheduler
// handles thousands of concurrent tunnels comfortably.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Hardening defaults — see the inline comments at usage sites.
const (
	// maxConcurrent caps how many tunnels can be open at once. Protects
	// against a misbehaving client fork-bombing CONNECT requests and
	// exhausting the pod's fd ulimit. 2000 is comfortably above the
	// expected steady-state (~ a few dozen) while well under typical
	// ulimit (~65535). New CONNECTs over the cap get 503 immediately.
	maxConcurrent = 2000
	// maxTunnelDuration is the absolute lifetime of a tunneled
	// connection — kills connections leaked by half-open peers or
	// broken NATs. Generous vs. the crawler's actual tunnel lifetime
	// (sub-second to seconds; max-life on the pool is 2 s).
	maxTunnelDuration = 10 * time.Minute
	// requestBufSize sets the bufio.Reader buffer for parsing the
	// CONNECT request line + headers. Default 4 KB can ErrBufferFull
	// on pathological clients with many proxy headers; 16 KB is the
	// same size envoy uses internally.
	requestBufSize = 16 * 1024
	// connectParseTimeout bounds how long we wait for the client to
	// send the full CONNECT request line + headers. Sane clients send
	// them in one packet; this catches slow-loris-style stalls.
	connectParseTimeout = 5 * time.Second
	// upstreamDialTimeout bounds the TCP dial to the upstream. The
	// VPN tunnel's path can be slow; envoy default is 5 s, we go 8 s.
	upstreamDialTimeout = 8 * time.Second
)

// Server is the HTTP CONNECT proxy.
type Server struct {
	addr    string
	podName string
	nodeIP  string

	exitIP   atomic.Value // string; updated by SetExitIP
	draining atomic.Bool  // when true, refuse new CONNECTs with 503

	listener net.Listener

	// concurrency limiter — buffered chan as semaphore. Acquired
	// non-blockingly before handle(); failed acquires return 503.
	sem chan struct{}

	// stats
	totalConnect    atomic.Uint64
	totalSuccess    atomic.Uint64
	totalError      atomic.Uint64
	totalDraining   atomic.Uint64
	totalOverloaded atomic.Uint64
	openTunnels     atomic.Int64

	// Upstream-dial outcome tracking — the watchdog's source of truth
	// for "is the tunnel actually delivering packets right now?"
	//
	// Each call to net.DialTimeout in handle() flows through
	// recordDial, which updates these three atomics. The watchdog
	// reads TunnelHealth() and decides whether to attempt a reconnect
	// based on real traffic outcomes, NOT on a synthetic poll through
	// the VPN daemon's CLI (which can wedge while the data plane is
	// fine — see the expressvpn-1 incident write-up).
	//
	// lastDialAtUnixNano is the wall-clock time of the most recent
	// dial completion (success or failure). Zero means "no dial yet."
	// The watchdog treats "no dial recently" as "no signal" and
	// abstains.
	//
	// lastDialOK records the outcome of the most recent dial. Useful
	// shorthand for "is the very latest signal positive?"
	//
	// consecutiveDialFails is the streak of failures since the last
	// success — reset on any success. The watchdog only attempts a
	// reconnect when this exceeds a small threshold (so a single
	// transient upstream blip doesn't trigger needless rotation).
	lastDialAtUnixNano   atomic.Int64
	lastDialOK           atomic.Bool
	consecutiveDialFails atomic.Int64
}

// TunnelHealth is the proxy's view of recent upstream-dial outcomes,
// consumed by the watchdog instead of the per-provider CLI Connected()
// probe. See Server.RecentTunnelHealth.
type TunnelHealth struct {
	LastDialAt          time.Time
	LastDialSucceeded   bool
	ConsecutiveFailures int64
}

// New constructs a Server bound (but not yet listening) at addr.
// podName / nodeIP are static for the pod's lifetime and surface as
// x-tundler-tunnel-id / x-tundler-node-ip on every successful CONNECT
// response.
func New(addr, podName, nodeIP string) *Server {
	s := &Server{
		addr:    addr,
		podName: podName,
		nodeIP:  nodeIP,
		sem:     make(chan struct{}, maxConcurrent),
	}
	s.exitIP.Store("")
	return s
}

// SetExitIP updates the x-tundler-exit-ip header value. Safe to call
// from any goroutine; takes effect on the next CONNECT response.
// Empty string means "no exit IP known yet" — the header is then
// omitted from responses entirely.
func (s *Server) SetExitIP(ip string) { s.exitIP.Store(ip) }

// SetDraining toggles drain mode. When draining, the proxy still
// accepts connections but immediately returns 503 to CONNECT
// requests — used during VPN rotation so in-flight CONNECTs finish
// cleanly but new ones are bounced to other tunnel pods by the
// crawler's slot logic.
func (s *Server) SetDraining(draining bool) { s.draining.Store(draining) }

// IsDraining reports the current drain flag. Test seam (also useful
// for /status).
func (s *Server) IsDraining() bool { return s.draining.Load() }

// IncOpenTunnels adjusts the open-tunnel counter by delta. Test
// seam for the drain controller — production handle() uses this
// internally to track active tunnels.
func (s *Server) IncOpenTunnels(delta int64) { s.openTunnels.Add(delta) }

// recordDial logs the outcome of one upstream dial. Called from
// handle() right after net.DialTimeout returns — success means we
// got a TCP connection to the upstream through the VPN tunnel,
// failure means we didn't (timeout, refused, route missing, etc.).
//
// All three fields are atomic so this is safe to call from many
// goroutines without locking.
func (s *Server) recordDial(success bool) {
	s.lastDialAtUnixNano.Store(time.Now().UnixNano())
	s.lastDialOK.Store(success)
	if success {
		s.consecutiveDialFails.Store(0)
	} else {
		s.consecutiveDialFails.Add(1)
	}
}

// SeedDialOutcome is a TEST SEAM: drives the dial-outcome state from
// outside handle() so the watchdog tests can exercise health
// transitions without spinning up real upstreams. Production code
// reaches recordDial via handle() — never call SeedDialOutcome from
// non-test code.
func (s *Server) SeedDialOutcome(success bool) { s.recordDial(success) }

// RecentTunnelHealth snapshots the current upstream-dial state for
// the watchdog. Returned LastDialAt is the zero value when no dial
// has happened yet — the watchdog treats that as "no signal."
func (s *Server) RecentTunnelHealth() TunnelHealth {
	var t time.Time
	if ns := s.lastDialAtUnixNano.Load(); ns != 0 {
		t = time.Unix(0, ns)
	}
	return TunnelHealth{
		LastDialAt:          t,
		LastDialSucceeded:   s.lastDialOK.Load(),
		ConsecutiveFailures: s.consecutiveDialFails.Load(),
	}
}

// Stats returns a snapshot of cumulative counters. Useful for log
// reporting and exposing via the existing /status JSON endpoint.
func (s *Server) Stats() Stats {
	return Stats{
		TotalConnect:    s.totalConnect.Load(),
		TotalSuccess:    s.totalSuccess.Load(),
		TotalError:      s.totalError.Load(),
		TotalDraining:   s.totalDraining.Load(),
		TotalOverloaded: s.totalOverloaded.Load(),
		OpenTunnels:     s.openTunnels.Load(),
	}
}

// Stats is the counter snapshot returned by Server.Stats.
type Stats struct {
	TotalConnect    uint64 `json:"total_connect"`
	TotalSuccess    uint64 `json:"total_success"`
	TotalError      uint64 `json:"total_error"`
	TotalDraining   uint64 `json:"total_draining"`
	TotalOverloaded uint64 `json:"total_overloaded"`
	OpenTunnels     int64  `json:"open_tunnels"`
}

// Serve binds and runs the proxy until ctx is cancelled. Blocks
// until cancelled or a fatal Accept error occurs.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = ln
	log.Printf("proxy: listening on %s", s.addr)

	// Close listener when ctx done so Accept unblocks.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			// Transient accept error (e.g. EMFILE) — log and keep
			// going, briefly backing off so a tight loop doesn't
			// burn CPU.
			log.Printf("proxy: accept: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go s.handle(conn)
	}
}

// handle services one client connection: parse CONNECT, dial
// upstream, write 200 + headers, splice bytes both ways until either
// side EOFs OR maxTunnelDuration is hit (whichever first).
func (s *Server) handle(client net.Conn) {
	defer client.Close()
	s.totalConnect.Add(1)

	// Try to acquire a concurrency token NON-BLOCKINGLY. If the
	// semaphore is full we'd rather fail fast with 503 than queue
	// the client and let it time out. The crawler then retries on
	// another slot.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.totalOverloaded.Add(1)
		writeError(client, 503, "Service Unavailable (overloaded)")
		return
	}

	// Bound the parse phase. The request line + headers should be in
	// the first packet from a sane client; connectParseTimeout is
	// generous. Reset to maxTunnelDuration once the tunnel is up.
	_ = client.SetReadDeadline(time.Now().Add(connectParseTimeout))

	// 16 KB buffer (vs Go's default 4 KB) to tolerate clients that
	// stack many proxy headers — matches envoy's request buffer size.
	br := bufio.NewReaderSize(client, requestBufSize)
	target, err := parseConnect(br)
	if err != nil {
		s.totalError.Add(1)
		writeError(client, 400, "Bad Request")
		return
	}

	if s.draining.Load() {
		s.totalDraining.Add(1)
		writeError(client, 503, "Service Unavailable (draining)")
		return
	}

	// Dial upstream. Go's default resolver caches via the host's
	// nsswitch + glibc cache; sufficient for our load.
	upstream, err := net.DialTimeout("tcp", target, upstreamDialTimeout)
	s.recordDial(err == nil)
	if err != nil {
		s.totalError.Add(1)
		writeError(client, 502, "Bad Gateway")
		return
	}
	defer upstream.Close()

	// Tunnel is established — write the success response with
	// tundler-* headers. Spec: "200 OK" or "200 Connection
	// established" both accepted by clients in practice; envoy uses
	// the latter so we match for consistency.
	if err := writeConnectResponse(client, s.podName, s.nodeIP, s.exitIP.Load().(string)); err != nil {
		s.totalError.Add(1)
		return
	}
	s.totalSuccess.Add(1)
	s.openTunnels.Add(1)
	defer s.openTunnels.Add(-1)

	// Absolute deadline on the tunnel — protects against leaked
	// half-open connections (broken NAT, killed peer). Generous vs.
	// crawler's actual tunnel lifetime (sub-second to a few seconds;
	// HttpFetchService caps connection life at 2 s). Anything still
	// alive after this is almost certainly leaked.
	tunnelDeadline := time.Now().Add(maxTunnelDuration)
	_ = client.SetReadDeadline(tunnelDeadline)
	_ = upstream.SetReadDeadline(tunnelDeadline)

	// Bidirectional splice. Two goroutines so both directions can
	// proceed independently; wait for both to finish before
	// returning (so deferred Close runs after the tunnel is fully
	// drained).
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, br) // forward: client → upstream
		halfClose(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream) // backward: upstream → client
		halfClose(client)
	}()
	wg.Wait()
}

// parseConnect reads and validates the CONNECT request line +
// headers from br. Returns the target host:port from the request
// line. Headers are discarded — we don't pass any client headers
// through, matching envoy's CONNECT behavior.
func parseConnect(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) != 3 || !strings.EqualFold(parts[0], "CONNECT") {
		return "", errors.New("not a CONNECT request")
	}
	target := parts[1]
	if !strings.Contains(target, ":") {
		return "", errors.New("CONNECT target missing port")
	}
	// Consume remaining headers up to the blank line. Cheap
	// loop — typical CONNECT has 1-5 headers.
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(h) == "" {
			return target, nil
		}
	}
}

// writeConnectResponse writes the 200 Connection established line
// plus tundler-* headers, then the empty-line terminator. Matches
// envoy's CONNECT response shape (which the crawler / hub envoy
// already parse correctly).
func writeConnectResponse(w io.Writer, podName, nodeIP, exitIP string) error {
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 200 Connection established\r\n")
	if podName != "" {
		sb.WriteString("x-tundler-tunnel-id: ")
		sb.WriteString(podName)
		sb.WriteString("\r\n")
	}
	if nodeIP != "" {
		sb.WriteString("x-tundler-node-ip: ")
		sb.WriteString(nodeIP)
		sb.WriteString("\r\n")
	}
	if exitIP != "" {
		sb.WriteString("x-tundler-exit-ip: ")
		sb.WriteString(exitIP)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")
	_, err := w.Write([]byte(sb.String()))
	return err
}

// writeError sends a minimal HTTP/1.1 error response to client.
// Best-effort — clients that have already given up don't matter.
func writeError(w io.Writer, code int, msg string) {
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 ")
	sb.WriteString(itoa(code))
	sb.WriteString(" ")
	sb.WriteString(msg)
	sb.WriteString("\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	_, _ = w.Write([]byte(sb.String()))
}

func itoa(n int) string {
	// Small status-code formatter; avoids strconv import for this
	// one call. n is always 3 digits (HTTP status).
	return string([]byte{byte('0' + n/100), byte('0' + (n/10)%10), byte('0' + n%10)})
}

// halfClose attempts a one-way close on the TCP connection (FIN to
// the peer, still readable). Falls back to Close() on non-TCP.
func halfClose(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	_ = c.Close()
}
