package pia

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const bin = "piactl"
const name = "pia"

// rateLimitCooldown is how long Login refuses to call piactl after PIA's
// auth API has returned ApiRateLimitedError. Chosen to outlast PIA's typical
// Cloudflare-style sliding-window rate limits (a few minutes to ~30 min) so
// repeated tundler restarts across a fleet don't keep hammering the API
// while it's already throttling us. The cooldown is per-process; if a pod
// restarts during it, the new process starts with a clean slate but will
// re-trigger the cooldown on the very next failed login response.
const rateLimitCooldown = 15 * time.Minute

type PIA struct{}

var (
	loggedIn          bool
	rateLimitedUntil  time.Time
	rateLimitMu       sync.Mutex
)

func init() { provider.Registry[name] = PIA{} }

func quiet(ctx context.Context, args ...string) { _, _ = shared.RunCmd(ctx, bin, args...) }

// desiredProtocol is the VPN transport tundler forces for PIA. piactl's
// Linux desktop default is OpenVPN (userspace, TLS-wrapped, single-
// threaded crypto — slow to handshake and low throughput); the mobile
// app defaults to WireGuard (kernel/near-instant, high throughput).
// tundler never overrode the default, so every PIA tunnel was crawling
// over the slow transport. PIA_PROTOCOL=openvpn reverts this without an
// image rebuild if WireGuard can't come up in a given container/node.
func desiredProtocol() string {
	if p := strings.TrimSpace(os.Getenv("PIA_PROTOCOL")); p != "" {
		return p
	}
	return "wireguard"
}

// ensureProtocol sets the transport to desiredProtocol(), but ONLY while
// the daemon is DISCONNECTED. `piactl set protocol` returns exit 0 even on
// a live tunnel, but immediately WEDGES the daemon (every subsequent
// piactl call then times out), so it must run before any Connect(). It is
// idempotent (skips when already set — so a reconnect mid-session never
// re-flips it) and best-effort: a not-yet-ready daemon reports a non-
// "Disconnected" state (or times out → empty), we skip, and the next
// Login() in connectTunnel's retry loop tries again before Connect.
func ensureProtocol(ctx context.Context) {
	want := desiredProtocol()
	if cur, _ := shared.RunCmd(ctx, bin, "get", "protocol"); strings.TrimSpace(cur) == want {
		return
	}
	state, _ := shared.RunCmd(ctx, bin, "get", "connectionstate")
	if strings.TrimSpace(state) != stateDisconnected {
		shared.Debugf("PIA: ensureProtocol - skip set (state=%q, not Disconnected)", strings.TrimSpace(state))
		return
	}
	shared.Debugf("PIA: ensureProtocol - setting protocol=%s while disconnected", want)
	quiet(ctx, "set", "protocol", want)
}

func (p PIA) ActiveLocation(ctx context.Context) string {
	out, _ := shared.RunCmd(ctx, bin, "get", "region")
	return strings.TrimSpace(out)
}

func (p PIA) Connect(ctx context.Context, location string) provider.Status {
	shared.Debugf("PIA: Connect() called with location: %s", location)

	if location != "" {
		shared.Debugf("PIA: Connect() - setting region to %s", location)
		quiet(ctx, "set", "region", location)
	}

	shared.Debugf("PIA: Connect() - initiating connection")
	quiet(ctx, "connect")

	// Poll the in-memory state populated by piactl monitor instead of
	// spawning piactl get repeatedly. Each iteration is a few atomic
	// reads — orders of magnitude cheaper than the old loop that paid
	// the piactl subprocess startup cost ~3 times per second. When
	// `piactl monitor` itself has failed enough times to flip
	// fallbackActive, we still call p.Status() but with a wider sleep
	// to reduce daemon contention.
	//
	// Log throttle: we used to emit one "waiting: connected=… ip=…"
	// per poll (every 250 ms), which produced ~30 noise lines in the
	// typical 8 s connect window. The poll itself runs every 250 ms
	// for fast first-success detection; the LOG runs at most once per
	// 5 s so journals stay readable. The state values we'd log
	// rarely change between sub-second polls anyway.
	deadline := time.Now().Add(60 * time.Second)
	lastLog := time.Time{}
	for time.Now().Before(deadline) {
		status := p.Status(ctx)
		if status.Connected && status.IP != "" {
			shared.Debugf("PIA: Connect() - connected with IP: %s", status.IP)
			return status
		}
		if time.Since(lastLog) >= 5*time.Second {
			shared.Debugf("PIA: Connect() - waiting: connected=%v, ip=%s", status.Connected, status.IP)
			lastLog = time.Now()
		}
		sleep := 250 * time.Millisecond
		if globalMonitor.inFallback() {
			sleep = 1 * time.Second
		}
		time.Sleep(sleep)
	}

	shared.Debugf("PIA: Connect() - timeout waiting for VPN IP")
	return p.Status(ctx)
}

// Connected reports whether the VPN tunnel is up.
//
// Reads from the piactl-monitor-backed in-memory state (no subprocess
// spawn). The pre-monitor implementation returned true for anything
// that didn't contain "disconnected", which counted transient states
// like "Connecting" / "Unknown" as connected and led Connect() to
// chase an IP that wasn't actually available. Now we require the
// state to be EXACTLY "Connected" (the documented stable connected
// state from `piactl monitor connectionstate`).
//
// Fallback: if the monitor has flipped to fallbackActive (subprocess
// died too many times), we do one direct piactl get call instead.
func (p PIA) Connected(ctx context.Context) bool {
	if globalMonitor.inFallback() {
		out, _ := shared.RunCmd(ctx, bin, "get", "connectionstate")
		return strings.TrimSpace(out) == stateConnected
	}
	return globalMonitor.state() == stateConnected
}

func (p PIA) Disconnect(ctx context.Context) error {
	shared.Debugf("PIA: Disconnect() called")

	shared.Debugf("PIA: Disconnect() - initiating disconnection")
	_, err := shared.RunCmd(ctx, bin, "disconnect")
	if err != nil {
		shared.Debugf("PIA: Disconnect() - disconnect command failed: %v", err)
		return err
	}

	// Wait for disconnection to complete and VPN IP to be removed. The
	// `disconnect` command above has already been sent (the backend frees
	// the session on that), so this loop is only confirmation — bail
	// promptly if ctx is cancelled (e.g. a shutdown teardown bounded by
	// gracefulDisconnect's 8s / systemd's 10s stop window) rather than
	// blocking the full 30s and risking a SIGKILL mid-wait.
	shared.Debugf("PIA: Disconnect() - waiting for VPN IP removal")
	for i := 0; i < 30; i++ { // Wait up to 30 seconds
		status := p.Status(ctx)
		if !status.Connected && status.IP == "" {
			shared.Debugf("PIA: Disconnect() - disconnected, VPN IP removed")
			return nil
		}
		shared.Debugf("PIA: Disconnect() - attempt %d: connected=%v, ip=%s", i+1, status.Connected, status.IP)
		select {
		case <-ctx.Done():
			shared.Debugf("PIA: Disconnect() - ctx cancelled while awaiting IP removal (disconnect already sent): %v", ctx.Err())
			return nil
		case <-time.After(1 * time.Second):
		}
	}

	shared.Debugf("PIA: Disconnect() - timeout waiting for VPN IP removal")
	return nil
}

func (p PIA) Locations(ctx context.Context) []string {
	out, _ := shared.RunCmd(ctx, bin, "get", "regions")
	var regions []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			regions = append(regions, line)
		}
	}
	return regions
}

func (p PIA) LoggedIn(ctx context.Context) bool {
	if loggedIn {
		return true
	}
	// Check if credentials are available (required for login)
	username := os.Getenv("PRIVATEINTERNETACCESS_USERNAME")
	password := os.Getenv("PRIVATEINTERNETACCESS_PASSWORD")
	if username == "" || password == "" {
		shared.Debugf("PIA: LoggedIn() - missing credentials")
	}
	return false
}

func (p PIA) Login(ctx context.Context) error {
	shared.Debugf("PIA: Login() called")

	username := os.Getenv("PRIVATEINTERNETACCESS_USERNAME")
	password := os.Getenv("PRIVATEINTERNETACCESS_PASSWORD")

	if username == "" || password == "" {
		shared.Debugf("PIA: Login() - missing credentials")
		return fmt.Errorf("PRIVATEINTERNETACCESS_USERNAME and PRIVATEINTERNETACCESS_PASSWORD environment variables must be set")
	}

	// Honor any active rate-limit cooldown — refuse to call piactl while
	// PIA's auth API is still throttling us. This prevents fleets of
	// pods restarting in close succession from continuously re-triggering
	// the rate limit (which is what produced the multi-hour PIA outage
	// observed in the 2026-05-17 incident).
	rateLimitMu.Lock()
	until := rateLimitedUntil
	rateLimitMu.Unlock()
	if remaining := time.Until(until); remaining > 0 {
		shared.Debugf("PIA: Login() - skipping piactl call, rate-limit cooldown %s remaining",
			remaining.Round(time.Second))
		return fmt.Errorf("pia api rate-limited, cooldown %s remaining", remaining.Round(time.Second))
	}

	shared.Debugf("PIA: Login() - enabling background")
	quiet(ctx, "background", "enable")

	// Force WireGuard on the fresh, still-disconnected daemon BEFORE the
	// first Connect — the desktop default is slow OpenVPN. Safe here
	// because no tunnel is up yet (flipping protocol live wedges the
	// daemon); idempotent on later calls. See ensureProtocol.
	ensureProtocol(ctx)

	shared.Debugf("PIA: Login() - checking if already logged in")
	if p.LoggedIn(ctx) {
		shared.Debugf("PIA: Login() - already logged in, skipping")
		return nil
	}

	shared.Debugf("PIA: Login() - not logged in, proceeding with login")
	credentialsFile := "/tmp/pia_credentials"
	credentials := fmt.Sprintf("%s\n%s", username, password)

	if err := os.WriteFile(credentialsFile, []byte(credentials), 0600); err != nil {
		shared.Debugf("PIA: Login() - failed to write credentials file: %v", err)
		return fmt.Errorf("failed to write credentials file: %w", err)
	}
	defer os.Remove(credentialsFile)

	// PIA daemon can take up to ~60s to initialize its network stack.
	// Use a generous piactl timeout to avoid rate-limiting from rapid retries.
	shared.Debugf("PIA: Login() - executing login command")
	out, err := shared.RunCmd(ctx, bin, "--timeout", "90", "login", credentialsFile)
	shared.Debugf("PIA: Login() - login output: %s, err: %v", out, err)

	// Success paths: exit 0 (fresh login), or output contains the historical
	// "Already logged into account" marker (older piactl versions returned
	// exit 127 with this output). Modern piactl (3.7.2+) returns exit 0 on
	// fresh login and proper non-zero codes on failure — the marker check
	// is kept for backwards-compat with older builds in the wild.
	if err == nil || strings.Contains(out, "Already logged into account") {
		shared.Debugf("PIA: Login() - login successful")
		loggedIn = true
		// Daemon is responsive and we're authenticated — safe to
		// spawn the piactl monitor subprocesses now. Idempotent
		// (sync.Once internally) so subsequent Login() calls don't
		// re-spawn.
		globalMonitor.start()
		return nil
	}

	// PIA's auth API returns "ApiRateLimitedError" (Cloudflare-style sliding-
	// window throttle) when too many login attempts come from one account in
	// a short period. Record a cooldown and return a distinct error so callers
	// can distinguish rate-limit from credential/network failures. The
	// piactl --debug output puts the literal "ApiRateLimitedError" string in
	// stderr; RunCmd captures both stdout and stderr into `out`.
	if strings.Contains(out, "ApiRateLimitedError") {
		rateLimitMu.Lock()
		rateLimitedUntil = time.Now().Add(rateLimitCooldown)
		rateLimitMu.Unlock()
		shared.Debugf("PIA: Login() - PIA API rate-limited, cooldown %s set", rateLimitCooldown)
		return fmt.Errorf("pia api rate-limited, will retry after %s", rateLimitCooldown)
	}

	shared.Debugf("PIA: Login() - login failed: %v", err)
	return fmt.Errorf("pia login failed: %w", err)
}

func (p PIA) Logout(ctx context.Context) error {
	loggedIn = false
	_, err := shared.RunCmd(ctx, bin, "logout")
	return err
}

// Status returns the latest VPN status. Sources:
//   - Connection state: from globalMonitor (piactl monitor
//     connectionstate), no subprocess spawn.
//   - VPN IP: from globalMonitor (piactl monitor vpnip), no spawn.
//   - Region: still requires a piactl get (region isn't on the
//     `piactl monitor` value list we care about, and it changes
//     rarely — once per VPN session).
//
// When the monitor has flipped to fallbackActive, all three values
// come from one-shot piactl get instead.
func (p PIA) Status(ctx context.Context) provider.Status {
	connected := p.Connected(ctx)

	status := provider.Status{
		Connected: connected,
		Provider:  name,
	}

	if connected {
		status.Location = p.ActiveLocation(ctx)
		status.Region = status.Location

		if globalMonitor.inFallback() {
			if out, err := shared.RunCmd(ctx, bin, "get", "vpnip"); err == nil {
				status.IP = shared.FirstIPv4(out)
			}
		} else {
			status.IP = shared.FirstIPv4(globalMonitor.ip())
		}
	}

	return status
}

func (p PIA) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, bin, "--version")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(out), nil
}
