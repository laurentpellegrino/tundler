package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// egressCheckURL is the upstream we probe to learn what source IP
// the world sees us from. Plain text body containing the IP and
// nothing else — used by countless tools, so we don't get blocked
// even from datacenter ranges. Probing it both pre- and post-VPN
// catches the class of bug where a provider's tunnel ends up in
// the wrong netns: Connect succeeds, /status looks Ready, but
// crawler traffic actually exits via the pod's node IP.
//
// Kept as a const (not env-overrideable) deliberately: a node-IP
// leak is the kind of contract violation an operator should not
// be able to silently disable through misconfiguration.
const egressCheckURL = "https://checkip.amazonaws.com"

// egressProbeTimeout bounds a single probe attempt. Pre-VPN baseline
// runs once at boot and we can afford the cost; the post-Connect
// check fires on every rotation and on first connect, so the
// timeout needs to be tight enough that a slow probe doesn't cost
// us live throughput while remaining loose enough to absorb the
// post-handshake settle period of a fresh tunnel (DNS + TLS +
// HTTP all within the window).
const egressProbeTimeout = 8 * time.Second

// probeEgressIP returns the source IPv4 the egress endpoint sees
// when we call it from THIS process. Two important properties:
//
//   - Uses http.DefaultClient — the dial path is the same one the
//     in-process CONNECT proxy uses (plain net.DialTimeout, no
//     fwmark, no netns wrapping), so a leak that bypasses the
//     proxy's intended VPN tunnel is the SAME class of leak this
//     probe surfaces. If this probe sees the node IP, the proxy
//     will too.
//   - Read-bounded to 64 bytes (IPv4 max is 15 chars + newline);
//     pathological responses can't OOM us.
func probeEgressIP(ctx context.Context) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, egressProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, egressCheckURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("egress probe: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// errExitIPLeak is the canonical signal that a Connect succeeded
// at the link/route layer but post-connect traffic still exits via
// the pre-VPN baseline IP (= no actual tunneling). Surfaced as an
// error so the caller's existing retry / fail-and-exit machinery
// drives the response — no separate code path.
var errExitIPLeak = fmt.Errorf("exit-ip leak: post-VPN egress matches pre-VPN baseline")

// verifyExitIPDiffers probes the egress endpoint and returns nil if
// the observed IP differs from baseline (= the tunnel is genuinely
// routing traffic out a different source). If the probe itself
// fails — usually a transient post-Connect settle — we soft-pass:
// the watchdog runs anyway and will catch a wedged tunnel via
// dial-failure tracking. We only fail the contract on a CONFIRMED
// equality, not on probe failure, because that would convert a
// network blip into a CrashLoopBackOff.
//
// `baseline == ""` means the pre-VPN baseline was unavailable
// (cluster egress firewall, probe endpoint unreachable, etc.).
// In that mode we can't compare, so we soft-pass with a warning.
func verifyExitIPDiffers(ctx context.Context, baseline string) error {
	if baseline == "" {
		log.Printf("tundler-tunnel: exit-ip contract: SKIPPED (no pre-VPN baseline)")
		return nil
	}
	observed, err := probeEgressIP(ctx)
	if err != nil {
		log.Printf("tundler-tunnel: exit-ip contract: probe error: %v — soft-pass (watchdog will catch a wedged tunnel)", err)
		return nil
	}
	if observed == baseline {
		return fmt.Errorf("%w (baseline=%s observed=%s)", errExitIPLeak, baseline, observed)
	}
	log.Printf("tundler-tunnel: exit-ip contract: OK (baseline=%s, post-VPN=%s)", baseline, observed)
	return nil
}
