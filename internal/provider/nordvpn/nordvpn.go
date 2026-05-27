package nordvpn

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

type NordVPN struct{}

const bin = "nordvpn"
const name = bin

// activeLocation is whatever string was passed to Connect — i.e. an
// entry from Locations() (the candidate pool the manager picks from).
// Reporting it verbatim from ActiveLocation guarantees a config
// block/allow list entry can match: pool ↔ Status.Location round-trip
// the same string. Parsing `nordvpn status` would yield "tn2.nordvpn.com"
// or "Cote d'Ivoire", neither of which appears in `nordvpn countries`.
var (
	activeLocation string
	activeMu       sync.RWMutex
)

func init() { provider.Registry[name] = NordVPN{} }

func quiet(ctx context.Context, args ...string) { _, _ = shared.RunCmd(ctx, bin, args...) }

func (n NordVPN) ActiveLocation(ctx context.Context) string {
	if !n.Connected(ctx) {
		return ""
	}
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (n NordVPN) activeHostname(ctx context.Context) string {
	out, _ := shared.RunCmd(ctx, bin, "status")
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "Hostname:") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "Hostname:"))
		}
	}
	return ""
}

func (n NordVPN) Connect(ctx context.Context, location string) provider.Status {
	// Disable firewall before connection to prevent API blocking
	quiet(ctx, "set", "firewall", "disabled")
	args := []string{"connect"}
	if location != "" {
		args = append(args, location)
	}
	quiet(ctx, args...)
	activeMu.Lock()
	activeLocation = location
	activeMu.Unlock()
	return n.Status(ctx)
}

func (n NordVPN) Connected(ctx context.Context) bool {
	out, _ := shared.RunCmd(ctx, bin, "status")
	return strings.Contains(out, "Status: Connected")
}

func (n NordVPN) Disconnect(ctx context.Context) error {
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
	_, err := shared.RunCmd(ctx, bin, "disconnect")
	return err
}

func (n NordVPN) Locations(ctx context.Context) []string {
	out, _ := shared.RunCmd(ctx, bin, "countries")
	return strings.Fields(out)
}

func (n NordVPN) LoggedIn(ctx context.Context) bool {
	// `nordvpn account` returns 0 + account-info when logged in,
	// non-zero + "You're not logged in." when not. Quick & doesn't
	// trigger the interactive OAuth flow that `nordvpn login` (no
	// args) starts — which would block waiting for browser auth
	// and balloon RunCmd's stdout buffer until OOM.
	_, err := shared.RunCmd(ctx, bin, "account")
	return err == nil
}

func (n NordVPN) Login(ctx context.Context) error {
	token := os.Getenv("NORDVPN_TOKEN")
	if token == "" {
		return fmt.Errorf("NORDVPN_TOKEN environment variable not set")
	}
	if n.LoggedIn(ctx) {
		return nil
	}
	// nordvpnd refuses to honor `nordvpn login --token …` until the
	// analytics-consent state is set (the daemon ships with
	// "consent: undefined" and gates all auth IPC behind it). The
	// per-provider configure.sh used to handle this at pod boot but
	// it runs BEFORE systemd starts the daemon, so the `nordvpn` CLI
	// can't reach the daemon and the call silently fails. Apply it
	// here at login time when the daemon is guaranteed to be up.
	//
	// The same applies to the baseline `nordvpn set …` config —
	// meshnet/notify off, NordLynx, no analytics, etc. Without these,
	// the daemon eagerly downloads the meshnet/libtelio/nordwhisper
	// remote configs which slows boot and burns memory.
	configureDaemon(ctx)
	if _, err := shared.RunCmd(ctx, bin, "login", "--token", token); err != nil {
		return fmt.Errorf("nordvpn login failed: %w", err)
	}
	return nil
}

// configureDaemon applies the baseline nordvpnd config that has to
// happen post-daemon-start but pre-login. Errors are non-fatal —
// each setting is best-effort, and the worst case (a setting that
// doesn't take) leaves nordvpnd in its default state for that knob.
func configureDaemon(ctx context.Context) {
	// Decline the analytics-consent prompt that gates all subsequent
	// IPC. Piping "n" into the interactive `nordvpn login` (no args)
	// dismisses the prompt without progressing into the OAuth flow.
	cmd := []string{"sh", "-c", `printf "n\n" | nordvpn login 2>/dev/null || true`}
	_, _ = shared.RunCmd(ctx, cmd[0], cmd[1:]...)

	// Baseline settings. lan-discovery=enable is intentional (lets
	// the pod talk to its sibling slot-controller via cluster DNS);
	// firewall off because we manage iptables ourselves; meshnet/
	// notify off to skip the eager remote-config fetch.
	for _, args := range [][]string{
		{"set", "analytics", "disabled"},
		{"set", "autoconnect", "disabled"},
		{"set", "firewall", "disabled"},
		{"set", "lan-discovery", "enable"},
		{"set", "meshnet", "off"},
		{"set", "notify", "off"},
		{"set", "pq", "on"},
		{"set", "technology", "NordLynx"},
	} {
		quiet(ctx, args...)
	}
}

func (n NordVPN) Logout(ctx context.Context) error {
	_, err := shared.RunCmd(ctx, bin, "logout", "--persist-token")
	return err
}

func (n NordVPN) Status(ctx context.Context) provider.Status {
	if !n.Connected(ctx) {
		return provider.Status{Connected: false}
	}
	out, _ := shared.RunCmd(ctx, bin, "status") // needed for the public IP
	return provider.Status{
		Connected: true,
		IP:        shared.FirstIPv4(out),
		Location:  n.ActiveLocation(ctx),
		Region:    n.activeHostname(ctx),
		Provider:  name,
	}
}

func (n NordVPN) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, bin, "--version")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(out), nil
}
