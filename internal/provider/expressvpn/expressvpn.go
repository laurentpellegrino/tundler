package expressvpn

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const bin = "expressvpnctl"
const name = "expressvpn"

// daemonService is the systemd unit running expressvpn-daemon inside the
// container (enabled by docker/providers/expressvpn/configure.sh).
const daemonService = "expressvpn-service.service"

// minDaemonRecoveryInterval throttles daemon restarts so a fundamentally
// broken daemon can't be bounced on every single connect retry.
const minDaemonRecoveryInterval = 60 * time.Second

// lastDaemonRecovery is the unix-seconds timestamp of the last daemon
// restart (one provider per process, so package state is fine).
var lastDaemonRecovery atomic.Int64

// cliMu serializes every expressvpnctl invocation. The official desktop
// client holds ONE long-lived IPC connection to expressvpn-daemon; tundler
// forks a fresh CLI per call, each opening a fresh connection to
// daemon.sock — sometimes concurrently (boot retry, rotator, watchdog).
// The daemon's IPC dispatcher deadlocks under exactly that pattern (futex
// hang; same binary is stable under the official client on a desktop).
// One-in-flight mimics the official client's access pattern and removes
// the concurrent-connection trigger.
var cliMu sync.Mutex

// run executes `expressvpnctl args...` with the process-wide CLI lock held.
// ALL expressvpnctl calls in this package must go through run/quiet/get.
func run(ctx context.Context, args ...string) (string, error) {
	cliMu.Lock()
	defer cliMu.Unlock()
	return shared.RunCmd(ctx, bin, args...)
}

type ExpressVPN struct{}

func init() { provider.Registry[name] = ExpressVPN{} }

func quiet(ctx context.Context, args ...string) { _, _ = run(ctx, args...) }

// get returns the trimmed stdout of `expressvpnctl get <key>`. When the CLI
// fails (non-zero exit, including its internal "Timed out after N sec"
// timeout), it returns "". Without this guard, error text would be propagated
// as a real value: callers like Locations() then split it on whitespace and
// produce garbage tokens that the manager picks at random and feeds back into
// `expressvpnctl connect <token>`, wasting every connect attempt where the
// daemon was momentarily slow.
func get(ctx context.Context, key string) string {
	out, err := run(ctx, "get", key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (e ExpressVPN) ActiveLocation(ctx context.Context) string {
	return strings.TrimSpace(get(ctx, "region"))
}

// daemonResponsive reports whether expressvpn-daemon currently answers CLI
// requests. expressvpnctl has its own internal ~5s IPC timeout: on a wedged
// daemon it prints "Timed out after N sec" and exits non-zero.
func daemonResponsive(ctx context.Context) bool {
	out, err := run(ctx, "status")
	return err == nil && !strings.Contains(out, "Timed out")
}

// ensureDaemonResponsive detects the daemon's known futex deadlock (main
// thread parked in futex_wait, zero CPU, every CLI call timing out —
// observed repeatedly in production, 2026-06) and recovers it by restarting
// the systemd unit. Crucially this recovery is LOGIN-FREE: the account/
// session state lives on disk (/opt/expressvpn/etc/account.json) and
// survives a daemon restart (validated 2026-06-09), so unlike a container
// restart it costs none of the login-rate budget that ExpressVPN's
// account-sharing heuristics watch. Restarts are throttled to one per
// minute; after restarting we wait (up to ~30s) for the daemon to answer
// again so the caller's connect attempt runs against a live daemon.
func ensureDaemonResponsive(ctx context.Context) {
	if daemonResponsive(ctx) {
		return
	}
	now := time.Now().Unix()
	last := lastDaemonRecovery.Load()
	if now-last < int64(minDaemonRecoveryInterval/time.Second) {
		return
	}
	if !lastDaemonRecovery.CompareAndSwap(last, now) {
		return // another goroutine is already recovering
	}
	log.Printf("expressvpn: daemon unresponsive (CLI timeout) — restarting %s (login-free recovery)", daemonService)
	if _, err := shared.RunCmd(ctx, "systemctl", "restart", daemonService); err != nil {
		log.Printf("expressvpn: daemon restart failed: %v", err)
		return
	}
	for i := 0; i < 15; i++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
		if daemonResponsive(ctx) {
			log.Printf("expressvpn: daemon responsive again after restart")
			return
		}
	}
	log.Printf("expressvpn: daemon still unresponsive %s after restart", "30s")
}

func (e ExpressVPN) Connect(ctx context.Context, location string) provider.Status {
	// 0. self-heal: if the daemon is wedged (futex deadlock, CLI timing
	// out), restart it BEFORE attempting to connect — login-free, so the
	// boot/rotation retry loops recover instead of spinning against a dead
	// daemon until the startup probe forces a container restart + re-login.
	ensureDaemonResponsive(ctx)

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
	_, err := run(ctx, "disconnect")
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
	// Self-heal BEFORE the retry loop. connectTunnel calls Locations()
	// before Connect(), so without this a wedged daemon never reaches
	// Connect()'s recovery: Locations() spins its full 12×10s budget,
	// returns nil, pickLocation fails, and the connect loop restarts —
	// observed in production (tundler-tunnel-expressvpn-1, 2026-06-10:
	// 40+ min of 10s-cadence CLI timeouts, zero daemon restarts, slot
	// frozen at observed=0).
	ensureDaemonResponsive(ctx)
	for attempt := 0; attempt < maxAttempts; attempt++ {
		out, err := run(ctx, "get", "regions")
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

	// Disable Network Lock (settings.json "killswitch": auto → off) BEFORE
	// anything else, on every boot — including the already-logged-in respawn
	// path below. At "auto" the daemon arms an iptables firewall (evpn.*
	// chains incl. blockDNS/blockAll hooked into OUTPUT) during every connect
	// transition; when the daemon hits its internal futex deadlock
	// mid-transition (observed 2026-06-09: every pod at once, DNS dead,
	// "Could not resolve host") the armed killswitch stays behind and
	// blackholes the pod's entire egress — turning a wedged daemon into an
	// unrecoverable, undiagnosable pod. We don't need the daemon's leak
	// protection: tundler gates traffic on /readyz and verifies the exit-IP
	// contract after every connect.
	//
	// The CLI key is "networklock" (NOT "killswitch", which the CLI rejects
	// with "Unknown type"). This call rides the daemon's IPC, so it is lost
	// if the daemon is wedged — the authoritative enforcement is the
	// ExecStartPre prestart script (docker/providers/expressvpn/
	// configure.sh) that patches settings.json before every daemon start;
	// this CLI call is belt-and-braces for a responsive daemon.
	//
	// Self-heal first: a tundler respawn into a container whose daemon is
	// already wedged would otherwise burn the whole boot path (LoggedIn
	// reads a timeout as "logged in", Locations returns nil) against a
	// dead daemon.
	ensureDaemonResponsive(ctx)
	quiet(ctx, "set", "networklock", "off")

	if e.LoggedIn(ctx) {
		return nil
	}

	const tmpFile = "/tmp/expressvpn-activation-code"
	if err := os.WriteFile(tmpFile, []byte(token+"\n"), 0o600); err != nil {
		return fmt.Errorf("cannot write activation code: %w", err)
	}

	if _, err := run(ctx, "login", "-t", "20", tmpFile); err != nil {
		return fmt.Errorf("expressvpnctl login failed: %w", err)
	}

	// ensure CLI usable without GUI
	quiet(ctx, "background", "enable")
	return nil
}

func (e ExpressVPN) LoggedIn(ctx context.Context) bool {
	out, _ := run(ctx, "status")
	return !strings.Contains(out, "Not logged in.")
}

func (e ExpressVPN) Logout(ctx context.Context) error {
	_, err := run(ctx, "logout")
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
	out, err := run(ctx, "-v")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(out), nil
}
