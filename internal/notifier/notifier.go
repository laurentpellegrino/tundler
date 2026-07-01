// Package notifier is tundler's generic, provider-agnostic event hook.
//
// It is the extension point other systems plug into: when enabled, tundler
// POSTs a small JSON event to one or more configured HTTP destinations on
// every tunnel-up and on a periodic heartbeat. tundler itself knows nothing
// about any particular subscriber — a destination is just a URL, an optional
// bearer token, and an optional whitelist of which event fields to send. This
// keeps subscriber-specific logic out of tundler entirely.
//
// Configuration is env-only, consistent with the rest of tundler:
//
//	TUNDLER_EVENT_SINKS              JSON array of destinations (see Sink). When
//	                                 empty/unset the hook is disabled.
//	TUNDLER_EVENT_INTERVAL_SECONDS   heartbeat cadence (default 300).
//
// Example TUNDLER_EVENT_SINKS:
//
//	[
//	  {"url":"https://example.test/events","token":"abc",
//	   "fields":["provider_id","exit_ip","node_ip","pod","timestamp"]},
//	  {"url":"https://audit.example/hook","fields":["provider_id","exit_ip"]}
//	]
//
// Event fields available for selection: type, provider_id, exit_ip, node_ip,
// pod, timestamp. An empty (or omitted) "fields" sends them all.
//
// # Security
//
//   - Egress path: webhook delivery must NOT traverse the VPN tunnel. The pod
//     exists to route traffic through a provider exit; sending events through
//     it would hand the exit/node-IP inventory and the bearer token to the
//     very provider being catalogued. Target an in-cluster destination (or
//     otherwise split-tunnel-excluded route) so events stay on the trusted
//     management network.
//   - Transport: use https for any destination outside the cluster. TLS
//     verification uses Go's defaults — never weaken it. As defense in depth
//     the bearer token is withheld from plaintext non-internal URLs.
//   - Secrets: the token is operator config sourced from a secret store; it is
//     never logged, and neither are event bodies. Rotating it requires a pod
//     restart (env is read once at start).
//   - Data minimization: push only the fields a destination needs via the
//     per-sink "fields" whitelist.
//   - Trust: sink config is taken only from the environment (operator/secret
//     store controlled), which is what keeps this from being an SSRF primitive
//     — do not wire untrusted input into TUNDLER_EVENT_SINKS.
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	envSinks           = "TUNDLER_EVENT_SINKS"
	envIntervalSeconds = "TUNDLER_EVENT_INTERVAL_SECONDS"
	defaultIntervalSec = 300
	httpTimeout        = 10 * time.Second
)

// Sink is one webhook destination.
type Sink struct {
	URL   string `json:"url"`
	Token string `json:"token,omitempty"`
	// Fields whitelists which event fields to push to this destination.
	// Empty means "send every field".
	Fields []string `json:"fields,omitempty"`
}

// SnapshotFunc returns the current event field set and whether there is
// anything worth sending (false when no tunnel/exit IP is established yet).
// The notifier adds "type" and "timestamp"; the caller supplies the rest.
type SnapshotFunc func() (map[string]any, bool)

// Notifier fans events out to all configured sinks.
type Notifier struct {
	sinks    []Sink
	interval time.Duration
	hc       *http.Client
	snapshot SnapshotFunc
}

// FromEnv builds a Notifier from the environment. The bool is false (and the
// pointer nil) when no sinks are configured, so the caller can skip wiring.
func FromEnv(snapshot SnapshotFunc) (*Notifier, bool) {
	raw := strings.TrimSpace(os.Getenv(envSinks))
	if raw == "" {
		return nil, false
	}

	var sinks []Sink
	if err := json.Unmarshal([]byte(raw), &sinks); err != nil {
		log.Printf("notifier: invalid %s (expected JSON array): %v — event hook disabled", envSinks, err)
		return nil, false
	}

	valid := sinks[:0]
	for _, s := range sinks {
		if strings.TrimSpace(s.URL) == "" {
			log.Printf("notifier: skipping sink with empty url")
			continue
		}
		// Pin the sink's hostname to an IP NOW, while the container still
		// uses cluster DNS. FromEnv runs before Login/Connect, and several
		// provider clients (expressvpn, veepn, windscribe) rewrite
		// resolv.conf to an in-tunnel resolver that cannot resolve
		// cluster-internal names — a dial-time lookup would then fail on
		// every emit. Boot-time pinning is bounded by the pod's own
		// recycle cadence, the same trade-off as the cluster-bypass route.
		s.URL = pinHost(s.URL)
		valid = append(valid, s)
	}
	if len(valid) == 0 {
		return nil, false
	}

	interval := time.Duration(defaultIntervalSec) * time.Second
	if v := os.Getenv(envIntervalSeconds); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			interval = time.Duration(n) * time.Second
		} else {
			log.Printf("notifier: invalid %s=%q — using default %ds", envIntervalSeconds, v, defaultIntervalSec)
		}
	}

	log.Printf("notifier: event hook enabled (%d sink(s), heartbeat=%s)", len(valid), interval)
	return &Notifier{
		sinks:    valid,
		interval: interval,
		hc:       &http.Client{Timeout: httpTimeout},
		snapshot: snapshot,
	}, true
}

// Run drives the heartbeat until ctx is cancelled (emits once up front).
func (n *Notifier) Run(ctx context.Context) {
	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()
	n.emit(ctx, "heartbeat")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.emit(ctx, "heartbeat")
		}
	}
}

// OnTunnelUp emits a one-shot "tunnel_up" event without blocking the caller
// (it runs on its own goroutine with an independent timeout, since tundler
// invokes the tunnel-up listener synchronously).
func (n *Notifier) OnTunnelUp() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
		defer cancel()
		n.emit(ctx, "tunnel_up")
	}()
}

// emit snapshots current state and POSTs the (per-sink projected) event to
// every destination. Best-effort: each failure is logged, none propagate.
func (n *Notifier) emit(ctx context.Context, eventType string) {
	base, ok := n.snapshot()
	if !ok {
		return
	}
	base["type"] = eventType
	base["timestamp"] = time.Now().UTC().Format(time.RFC3339)

	for _, sink := range n.sinks {
		payload := project(base, sink.Fields)
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("notifier: marshal for %s failed: %v", sink.URL, err)
			continue
		}
		n.post(ctx, sink, body)
	}
}

func (n *Notifier) post(ctx context.Context, sink Sink, body []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sink.URL, bytes.NewReader(body))
	if err != nil {
		log.Printf("notifier: build request for %s failed: %v", sink.URL, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if sink.Token != "" {
		// Defense in depth: never put the bearer token on the wire in
		// cleartext to an external host. https is always fine; plaintext is
		// only allowed to loopback / private / cluster-internal targets
		// (where traffic stays on the trusted network).
		if tokenAllowed(sink.URL) {
			req.Header.Set("Authorization", "Bearer "+sink.Token)
		} else {
			log.Printf("notifier: refusing to send bearer token to plaintext non-internal URL %s", sink.URL)
		}
	}

	resp, err := n.hc.Do(req)
	if err != nil {
		log.Printf("notifier: POST %s failed: %v", sink.URL, err)
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("notifier: %s rejected event: %s", sink.URL, resp.Status)
	}
}

// pinHost resolves rawURL's hostname once and rewrites the URL with the
// resolved IP (preferring IPv4). Returns the URL unchanged when the host is
// already an IP literal or when resolution fails (best effort — the dial will
// then surface the DNS error as before).
func pinHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil {
		return rawURL
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		log.Printf("notifier: boot-time resolve of %s failed (%v) — keeping hostname", host, err)
		return rawURL
	}
	picked := addrs[0]
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			picked = a
			break
		}
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(picked, port)
	} else if ip := net.ParseIP(picked); ip != nil && ip.To4() == nil {
		u.Host = "[" + picked + "]"
	} else {
		u.Host = picked
	}
	log.Printf("notifier: pinned sink host %s → %s", host, picked)
	return u.String()
}

// tokenAllowed reports whether it is safe to attach a bearer token to a
// request for rawURL: true for https, or for plaintext only when the host is
// loopback, a private (RFC 1918 / ULA) address, or a cluster-internal DNS
// name — i.e. the token never leaves the trusted network in the clear.
func tokenAllowed(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Scheme, "https") {
		return true
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	return strings.HasSuffix(host, ".svc") ||
		strings.HasSuffix(host, ".cluster.local") ||
		strings.HasSuffix(host, ".local")
}

// project returns base unchanged when fields is empty, otherwise a copy
// containing only the whitelisted keys that are present.
func project(base map[string]any, fields []string) map[string]any {
	if len(fields) == 0 {
		return base
	}
	out := make(map[string]any, len(fields))
	for _, f := range fields {
		if v, ok := base[f]; ok {
			out[f] = v
		}
	}
	return out
}
