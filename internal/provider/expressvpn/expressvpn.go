package expressvpn

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const bin = "expressvpnctl"
const name = "expressvpn"

type ExpressVPN struct{}

func init() { provider.Registry[name] = ExpressVPN{} }

func quiet(ctx context.Context, args ...string) { _, _ = shared.RunCmd(ctx, bin, args...) }

// get returns the trimmed stdout of `expressvpnctl get <key>`. When the CLI
// fails (non-zero exit, including its internal "Timed out after N sec"
// timeout), it returns "". Without this guard, error text would be propagated
// as a real value: callers like Locations() then split it on whitespace and
// produce garbage tokens that the manager picks at random and feeds back into
// `expressvpnctl connect <token>`, wasting every connect attempt where the
// daemon was momentarily slow.
func get(ctx context.Context, key string) string {
	out, err := shared.RunCmd(ctx, bin, "get", key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (e ExpressVPN) ActiveLocation(ctx context.Context) string {
	return strings.TrimSpace(get(ctx, "region"))
}

func (e ExpressVPN) Connect(ctx context.Context, location string) provider.Status {
	// 1. kick off the connection
	if location == "" {
		quiet(ctx, "connect")
	} else {
		quiet(ctx, "connect", location)
	}

	// 2. block until the tunnel is ready (or ctx/timeout is hit)
	const (
		pollEvery = 250 * time.Millisecond // how often to poll
		maxWait   = 30 * time.Second       // safety cap
	)
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()

	for {
		st := e.Status(ctx)
		if st.Connected && st.IP != "" { // tunnel really up
			return st
		}

		select {
		case <-waitCtx.Done(): // ctx cancelled or maxWait reached
			return st // best-effort status (likely disconnected)
		case <-ticker.C:
		}
	}
}

func (e ExpressVPN) Connected(ctx context.Context) bool {
	state := get(ctx, "connectionstate")
	return state == "Connected"
}

func (e ExpressVPN) Disconnect(ctx context.Context) error {
	_, err := shared.RunCmd(ctx, bin, "disconnect")
	return err
}

// Locations queries expressvpnctl for the list of available regions.
// Wraps the call in a retry loop because the ExpressVPN daemon
// occasionally wedges right after container start: a fresh `expressvpnd`
// can take 10-30 s to populate its server catalog from the activation
// API, and any `expressvpnctl get regions` call during that window hits
// the CLI's built-in 5 s timeout, returns exit-2, and the caller
// would otherwise see 0 locations → `no allowed locations` → exit 1
// → systemd restart → repeat. Two retries with a 2 s gap give the
// daemon a chance to finish loading before we declare it broken;
// past two retries we return nil and let the caller bail (kubelet's
// /livez 5 min grace then restarts the whole container, which clears
// any wedged daemon state).
func (e ExpressVPN) Locations(ctx context.Context) []string {
	for attempt := 0; attempt < 3; attempt++ {
		out, err := shared.RunCmd(ctx, bin, "get", "regions")
		if err == nil {
			if fields := strings.Fields(out); len(fields) > 0 {
				return fields
			}
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
			}
		}
	}
	return nil
}

func (e ExpressVPN) Login(ctx context.Context) error {
	token := os.Getenv("EXPRESSVPN_ACTIVATION_CODE")
	if token == "" {
		return fmt.Errorf("EXPRESSVPN_ACTIVATION_CODE environment variable not set")
	}

	if e.LoggedIn(ctx) {
		return nil
	}

	const tmpFile = "/tmp/expressvpn-activation-code"
	if err := os.WriteFile(tmpFile, []byte(token+"\n"), 0o600); err != nil {
		return fmt.Errorf("cannot write activation code: %w", err)
	}

	if _, err := shared.RunCmd(ctx, bin, "login", "-t", "20", tmpFile); err != nil {
		return fmt.Errorf("expressvpnctl login failed: %w", err)
	}

	// ensure CLI usable without GUI
	quiet(ctx, "background", "enable")
	return nil
}

func (e ExpressVPN) LoggedIn(ctx context.Context) bool {
	out, _ := shared.RunCmd(ctx, bin, "status")
	return !strings.Contains(out, "Not logged in.")
}

func (e ExpressVPN) Logout(ctx context.Context) error {
	_, err := shared.RunCmd(ctx, bin, "logout")
	return err
}

func (e ExpressVPN) Status(ctx context.Context) provider.Status {
	if e.Connected(ctx) {
		return provider.Status{
			Connected: true,
			IP:        shared.FirstIPv4(get(ctx, "vpnip")),
			Location:  e.ActiveLocation(ctx),
			Region:    e.ActiveLocation(ctx),
			Provider:  name,
		}
	}
	return provider.Status{Connected: false}
}

func (e ExpressVPN) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, bin, "-v")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(out), nil
}
