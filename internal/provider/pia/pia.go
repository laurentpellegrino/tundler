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
const name = "privateinternetaccess"

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

	// Wait for connection to establish and get VPN IP
	shared.Debugf("PIA: Connect() - waiting for VPN IP assignment")
	for i := 0; i < 60; i++ { // Wait up to 60 seconds
		status := p.Status(ctx)
		if status.Connected && status.IP != "" {
			shared.Debugf("PIA: Connect() - connected with IP: %s", status.IP)
			return status
		}
		shared.Debugf("PIA: Connect() - attempt %d: connected=%v, ip=%s", i+1, status.Connected, status.IP)
		time.Sleep(1 * time.Second)
	}

	shared.Debugf("PIA: Connect() - timeout waiting for VPN IP")
	return p.Status(ctx)
}

func (p PIA) Connected(ctx context.Context) bool {
	out, _ := shared.RunCmd(ctx, bin, "get", "connectionstate")
	return !strings.Contains(strings.ToLower(out), "disconnected")
}

func (p PIA) Disconnect(ctx context.Context) error {
	shared.Debugf("PIA: Disconnect() called")

	shared.Debugf("PIA: Disconnect() - initiating disconnection")
	_, err := shared.RunCmd(ctx, bin, "disconnect")
	if err != nil {
		shared.Debugf("PIA: Disconnect() - disconnect command failed: %v", err)
		return err
	}

	// Wait for disconnection to complete and VPN IP to be removed
	shared.Debugf("PIA: Disconnect() - waiting for VPN IP removal")
	for i := 0; i < 30; i++ { // Wait up to 30 seconds
		status := p.Status(ctx)
		if !status.Connected && status.IP == "" {
			shared.Debugf("PIA: Disconnect() - disconnected, VPN IP removed")
			return nil
		}
		shared.Debugf("PIA: Disconnect() - attempt %d: connected=%v, ip=%s", i+1, status.Connected, status.IP)
		time.Sleep(1 * time.Second)
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

func (p PIA) Status(ctx context.Context) provider.Status {
	connected := p.Connected(ctx)

	status := provider.Status{
		Connected: connected,
		Provider:  name,
	}

	if connected {
		status.Location = p.ActiveLocation(ctx)
		status.Region = status.Location

		if out, err := shared.RunCmd(ctx, bin, "get", "vpnip"); err == nil {
			status.IP = shared.FirstIPv4(out)
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
