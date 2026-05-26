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
	//
	// pollEvery=2s is deliberate. Each poll forks expressvpnctl, which
	// opens a fresh IPC connection to expressvpn-daemon and serializes
	// through its request handler. At the previous 250 ms cadence we
	// hammered the daemon with ~6 round-trips per second for the
	// entire connect window — that pressure right around the daemon's
	// own internal Connected-state transition is the leading
	// hypothesis for the IPC wedges we keep observing
	// (data plane up, control plane locked). Polling every 2 s is
	// still plenty for a state machine whose transitions happen in
	// seconds; in exchange the daemon spends ~95% less time servicing
	// our diagnostic queries during the most lock-sensitive phase.
	const (
		pollEvery = 2 * time.Second
		maxWait   = 30 * time.Second // safety cap
	)
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()

	// IPC-wedge tolerance: the ExpressVPN daemon has been observed to
	// stop answering expressvpnctl queries immediately after a
	// successful state transition to Connected — the tunnel is up
	// (tun0 installed, routes in place, packets flow) but our polls
	// to confirm read empty. Pre-fix, the loop's `Connected && IP
	// != ""` gate stayed false and we discarded a working tunnel,
	// failAndExit'd, kubelet-restarted, repeated.
	//
	// Track whether we ever observed Connected during this window.
	// If the deadline expires with the flag set, trust the earlier
	// signal: return Connected=true with whatever IP we managed to
	// capture (often empty). The rest of the system tolerates an
	// empty exit IP — leak detection reads it from /status (which
	// reflects whatever we stored here), and the next rotation will
	// query a fresh IP when the daemon's IPC has hopefully recovered.
	var sawConnected bool
	var bestIP string

	for {
		st := e.Status(ctx)
		if st.Connected && st.IP != "" { // happy path: full envelope captured
			return st
		}
		if st.Connected {
			sawConnected = true
			if st.IP != "" {
				bestIP = st.IP
			}
		}

		select {
		case <-waitCtx.Done(): // ctx cancelled or maxWait reached
			if sawConnected {
				shared.Debugf("ExpressVPN: Connect() returning Connected=true with IP=%q after CLI IPC wedge (daemon reported Connected during polling but later queries timed out)", bestIP)
				return provider.Status{
					Connected: true,
					IP:        bestIP,
					Location:  location,
					Region:    location,
					Provider:  name,
				}
			}
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
//
// Cold-start behaviour: a fresh expressvpnd reports only a single
// placeholder region — "smart" — while it asynchronously downloads
// the full ~212-region catalog from ExpressVPN's backend (typically
// takes 10–45 s depending on backend latency). We can't connect to
// "smart" usefully (its auto-pick chronically lands on saturated
// edges from cloud-provider IP ranges, so we exclude it via
// EXCLUDED_LOCATIONS) — but then a cold-start daemon hands us back
// exactly one region which the picker filters out, leaving zero
// candidates and triggering failAndExit.
//
// Detection: the daemon-still-loading signal is unambiguous — the
// response is literally [smart]. Treat that case (and CLI failures /
// empty output) as "retry"; treat anything else as a real catalog
// and return it. Up to 12 attempts × 5 s = 60 s budget matches the
// worst-case observed cold-start window.
func (e ExpressVPN) Locations(ctx context.Context) []string {
	const (
		maxAttempts = 12
		retryGap    = 5 * time.Second
	)
	for attempt := 0; attempt < maxAttempts; attempt++ {
		out, err := shared.RunCmd(ctx, bin, "get", "regions")
		if err == nil {
			fields := strings.Fields(out)
			if !isColdStartPlaceholder(fields) {
				return fields
			}
			if len(fields) > 0 {
				shared.Debugf("ExpressVPN: Locations() got cold-start placeholder %v, retrying", fields)
			}
		}
		if attempt < maxAttempts-1 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(retryGap):
			}
		}
	}
	return nil
}

// isColdStartPlaceholder reports whether the regions response looks
// like a freshly-booted daemon's placeholder (just "smart") rather
// than a real catalog. Empty input is also treated as "not loaded".
func isColdStartPlaceholder(fields []string) bool {
	return len(fields) == 0 || (len(fields) == 1 && fields[0] == "smart")
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
