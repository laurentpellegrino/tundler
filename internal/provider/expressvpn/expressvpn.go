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

func get(ctx context.Context, key string) string {
	out, _ := shared.RunCmd(ctx, bin, "get", key)
	return strings.TrimSpace(out)
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

func (e ExpressVPN) Locations(ctx context.Context) []string {
	out, _ := shared.RunCmd(ctx, bin, "get", "regions")
	return strings.Fields(out)
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

	if _, err := shared.RunCmd(ctx, bin, "login", tmpFile); err != nil {
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
