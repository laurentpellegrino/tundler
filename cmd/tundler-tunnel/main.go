// Command tundler-tunnel is the single-provider VPN runtime that runs
// in each per-provider tunnel pod. One Go binary owns the VPN
// provider, the HTTP CONNECT proxy on :8485, the control API on :4242
// (/livez /readyz /status /rotate), the watchdog, the hourly rotator,
// and the wedge guard. See cmd/tundler-tunnel/README.md for the full
// design.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	_ "github.com/laurentpellegrino/tundler/internal/provider/register"
	"github.com/laurentpellegrino/tundler/internal/proxy"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	envProvider              = "TUNDLER_TUNNEL_PROVIDER"
	envBootLoginJitterSec    = "BOOT_LOGIN_JITTER_SECONDS"
	envExcludedLocations     = "EXCLUDED_LOCATIONS"
	envWatchdogIntervalSec   = "TUNNEL_WATCHDOG_INTERVAL_SECONDS"
	envMinRotationSec        = "MIN_ROTATION_SECONDS"
	envMaxRotationSec        = "MAX_ROTATION_SECONDS"
	envWedgeGuardSec         = "WEDGE_GUARD_THRESHOLD_SECONDS"
	// Self-recycle: after RECYCLE_AFTER_SECONDS (jittered) OR
	// RECYCLE_AFTER_ROTATIONS, the pod gracefully drains and exits its
	// container so kubelet recreates it on the latest image + freshest env.
	// 0 = disabled (the default; set via env in the fleet).
	envRecycleAfterSec       = "RECYCLE_AFTER_SECONDS"
	envRecycleAfterRot       = "RECYCLE_AFTER_ROTATIONS"
	envPodName               = "POD_NAME"               // downward API; → x-tundler-tunnel-id
	envNodeIP                = "TUNDLER_TUNNEL_NODE_IP" // from caller; → x-tundler-node-ip
	defaultBootJitterSec     = 60
	defaultWatchdogIntervSec = 30
	// Rotation cadence: each interval (and the initial boot offset) is
	// a uniform random pick from [MIN_ROTATION_SECONDS, MAX_ROTATION_SECONDS].
	// Default 2-4 hours: long enough that we don't burn provider account
	// session limits churning IPs, short enough that any given exit IP
	// doesn't accumulate enough crawl footprint to be flagged by
	// per-IP fingerprinting heuristics. Operators can narrow the window
	// (e.g. min=max for a fixed cadence) or widen it (e.g. 1h-8h for
	// extra unpredictability).
	defaultMinRotationSec = 7200  // 2h
	defaultMaxRotationSec = 14400 // 4h
	defaultWedgeGuardSec     = 900  // 15 min — tunable via WEDGE_GUARD_THRESHOLD_SECONDS

	// Port the in-process Go CONNECT proxy listens on (replaces the
	// sibling envoy container retired in phase 4). The Service
	// publishes the same port; the crawler's TunnelSlot.proxyUrl
	// points here.
	proxyListenPort = 8485
)

// Watchdog reconnect backoff. The watchdog keeps retrying forever
// (no early exit on failure) — a single transient piactl/expressvpnctl
// blip used to permanently park the pod in Failed until the hourly
// rotator picked it up. With this loop, recovery happens within ~60s
// of the daemon recovering.
//
// vars (not consts) so tests can dial them down without going through
// a full dependency-injection refactor.
var (
	watchdogMinBackoff = 5 * time.Second
	watchdogMaxBackoff = 60 * time.Second
)

// Watchdog health-check tunables: how the watchdog decides whether the
// tunnel is alive from observed CONNECT-proxy traffic.
//
//	dialFailureThreshold — how many consecutive upstream-dial
//	    failures the proxy must rack up before the watchdog suspects
//	    the tunnel itself and attempts a reconnect. A single failure
//	    is noise (the upstream is just down for that one host);
//	    sustained consecutive failures means dials don't make it past
//	    tun0 at all.
//	dialSilenceWindow — if the proxy hasn't completed a dial in this
//	    long, the watchdog has no signal either way and abstains. The
//	    crawler runs ~continuously in our deployment so silence is
//	    unusual; when it does happen (idle slot, fresh boot), we'd
//	    rather wait for real traffic to speak than poke a possibly-
//	    wedged CLI.
const (
	dialFailureThreshold = 5
	dialSilenceWindow    = 2 * time.Minute
)

func main() {
	// Provider plugins log failures via shared.Debugf, which is a no-op
	// unless SetDebug(true) is called. In production we DO want those
	// lines — "no servers found", "AUTH_FAILED", "failed to write
	// config", "openvpn connection timeout" etc. are the only signal we
	// have for connect-path failures, and silencing them turns every
	// real-world bug into "initial connect failed" with no further info.
	shared.SetDebug(true)

	providerName := os.Getenv(envProvider)
	if providerName == "" {
		log.Fatalf("tundler-tunnel: %s must be set (e.g. expressvpn, nordvpn, pia)", envProvider)
	}

	jitterMax := getEnvInt(envBootLoginJitterSec, defaultBootJitterSec)

	prov, ok := provider.Registry[providerName]
	if !ok {
		log.Fatalf("tundler-tunnel: unknown provider %q (compiled-in providers: %v)",
			providerName, registryKeys())
	}
	// Make the provider reachable from every exit path so we always
	// disconnect the tunnel (release the account's device slot) before
	// the process/container goes away — see registerShutdownDisconnect.
	registerShutdownDisconnect(prov, providerName)

	// Wire state + HTTP server up front so probes can see the pod's
	// lifecycle from t=0 (Booting → LoggingIn → Ready / Failed).
	state := NewStateTracker(providerName)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// In-process Go HTTP CONNECT proxy — replaces the sibling envoy
	// container retired in phase 4 of the migration. Single process
	// for the whole tunnel pod: VPN provider + proxy + HTTP control
	// API, all sharing the same Go runtime + state.
	podName := os.Getenv(envPodName)
	if podName == "" {
		// Local-dev fallback. Real pods get POD_NAME via downward API.
		podName = "tundler-tunnel-local"
	}
	nodeIP := os.Getenv(envNodeIP)
	proxySrv := proxy.New(fmt.Sprintf("0.0.0.0:%d", proxyListenPort), podName, nodeIP)
	go func() {
		if err := proxySrv.Serve(ctx); err != nil {
			log.Printf("tundler-tunnel: proxy server: %v", err)
		}
	}()

	state.SetTunnelUpListener(func(exitIP string) {
		// In-process pointer swap — read by proxy.handle on every
		// subsequent CONNECT, no IPC, no file IO.
		proxySrv.SetExitIP(exitIP)
	})

	// Proxy-chain providers (TunnelBear) don't bring up a kernel
	// tunnel: they forward through an upstream HTTPS proxy by
	// installing a dialer on the proxy. Hand them the proxy server so
	// Connect/rotate can do so, and route the exit-IP contract probe
	// through that same dialer (a direct probe would bypass the
	// upstream proxy and read the node IP). Kernel-tunnel providers
	// implement neither hook and are unaffected.
	if pc, ok := prov.(interface{ AttachProxy(*proxy.Server) }); ok {
		pc.AttachProxy(proxySrv)
		contractProbeDialer = proxySrv.DialUpstream
	}

	// Capture the pod's pre-VPN egress IP so the post-Connect contract
	// check (verifyExitIPDiffers) has a baseline to compare against.
	// Runs BEFORE the rotation closure is constructed (so the closure
	// can capture it) and BEFORE Login/Connect (once the VPN tunnel
	// is up, "what's our egress IP" is what we're trying to verify,
	// not the baseline). A failed baseline probe is non-fatal: the
	// contract check degrades to a no-op with a logged warning, so a
	// cluster with strict pre-VPN egress restrictions still boots.
	baselineEgressIP, err := probeEgressIP(ctx)
	if err != nil {
		log.Printf("tundler-tunnel: pre-VPN baseline egress probe failed: %v — exit-ip contract test disabled", err)
		baselineEgressIP = ""
	} else {
		log.Printf("tundler-tunnel: pre-VPN baseline egress=%s", baselineEgressIP)
	}

	// /rotate handler invokes this closure in a goroutine; rotateIfReady
	// guards on state==Ready internally so this is safe to call even if
	// the hourly rotator timer is racing with an HTTP-driven rotation.
	// The drain controller now backs onto the in-process proxy (no more
	// envoy admin HTTP calls).
	excluded := parseExcludedLocations(os.Getenv(envExcludedLocations))
	drain := newProxyDrainController(proxySrv)
	triggerRotation := func() {
		rotateIfReady(ctx, prov, state, providerName, excluded, drain, baselineEgressIP)
	}

	go func() {
		if err := startServer(ctx, state, triggerRotation, podName, nodeIP); err != nil {
			log.Fatalf("tundler-tunnel: HTTP server: %v", err)
		}
	}()

	d := pickJitter(jitterMax)
	state.RecordBootLoginJitter(d)
	log.Printf("tundler-tunnel: provider=%s boot_login_jitter_actual=%s (max=%ds) — sleeping then logging in",
		providerName, d, jitterMax)
	time.Sleep(d)

	state.Set(StateLoggingIn)
	if err := prov.Login(ctx); err != nil {
		// Bump the auth-failure counter BEFORE failAndExit. The
		// counter is what /status exposes for fleet-wide
		// alerting; surfacing it for at least the few seconds
		// kubelet takes to observe the crash is what makes a
		// "credentials drift" vs "transient network" distinction
		// visible without per-pod log inspection.
		state.RecordAuthFailure(err.Error())
		// Initial-login failure handling: flip state to Failed (so /livez
		// returns 503 within the next probe period — k8s sees the failure
		// and CrashLoopBackOff kicks in), give probes a moment to pick up
		// the new state, then exit non-zero.
		log.Printf("tundler-tunnel: initial login failed for provider=%s: %v", providerName, err)
		failAndExit(state)
	}

	// Tunnel hold: pick a random allowed location (provider-filtered minus
	// EXCLUDED_LOCATIONS) and Connect, retrying IN-PROCESS with backoff
	// until it succeeds. Crucially we do NOT re-login and do NOT exit on a
	// connect failure: the session token is established once by Login()
	// above, and a container restart would force a fresh login — re-login
	// storms are what trip a provider's shared-account / device-limit
	// throttle. /readyz stays 503 while we retry, so no traffic is routed
	// here until the tunnel is actually up. `excluded` is captured in
	// triggerRotation above; reuse it here.
	if err := connectInitialWithRetry(ctx, prov, state, providerName, excluded, baselineEgressIP, bootConnectBackoff); err != nil {
		// Returns only on ctx cancellation — the pod is shutting down
		// mid-connect. Release any half-up session and exit cleanly.
		log.Printf("tundler-tunnel: shutting down during initial connect: %v", err)
		gracefulDisconnect()
		return
	}

	// Start the watchdog: detects unexpected tunnel drops and reconnects
	// to a (possibly different) random allowed location. The design doc
	// says drops should reconnect WITHOUT a re-login (login is one-shot;
	// session token cached by the VPN client).
	watchdogInterval := time.Duration(getEnvInt(envWatchdogIntervalSec, defaultWatchdogIntervSec)) * time.Second
	go runWatchdog(ctx, prov, state, providerName, excluded, watchdogInterval, proxySrv, baselineEgressIP)

	// Start the rotator: each interval is a fresh uniform random pick
	// from [MIN_ROTATION_SECONDS, MAX_ROTATION_SECONDS] (defaults 2h-4h),
	// at which point we pick a fresh allowed location and rotate. The
	// initial boot offset is sampled from the same window, so a fleet
	// that boots together is spread across the full max-window from
	// the first rotation onward (no synchronized stampede).
	//
	// Operator-visible behavior:
	//   MIN_ROTATION_SECONDS == MAX_ROTATION_SECONDS == 0 → periodic rotation disabled
	//   MIN_ROTATION_SECONDS == MAX_ROTATION_SECONDS      → fixed cadence
	//   MIN_ROTATION_SECONDS <  MAX_ROTATION_SECONDS      → randomized within window
	//   MIN_ROTATION_SECONDS >  MAX_ROTATION_SECONDS      → falls back to min == max (logged)
	//
	// The disabled mode keeps /rotate available — crawler-driven rotation
	// (AIMD-triggered POST /rotate) still works; only the scheduled
	// timer is silenced. Useful for debug pods or single-shot tunnels.
	minRotation := time.Duration(getEnvInt(envMinRotationSec, defaultMinRotationSec)) * time.Second
	maxRotation := time.Duration(getEnvInt(envMaxRotationSec, defaultMaxRotationSec)) * time.Second
	if maxRotation < minRotation {
		log.Printf("tundler-tunnel: MAX_ROTATION_SECONDS (%s) < MIN_ROTATION_SECONDS (%s); clamping max=min",
			maxRotation, minRotation)
		maxRotation = minRotation
	}
	rotationEnabled := minRotation > 0 || maxRotation > 0
	if rotationEnabled {
		go runRotator(ctx, prov, state, providerName, excluded, minRotation, maxRotation, drain, baselineEgressIP)
	} else {
		log.Printf("tundler-tunnel: periodic rotation disabled (MIN_ROTATION_SECONDS=MAX_ROTATION_SECONDS=0); /rotate still honored")
	}

	// Wedge guard: if state stays continuously not-Ready for longer
	// than WEDGE_GUARD_THRESHOLD_SECONDS (default 15 min), the watchdog
	// has exhausted its retries on something genuinely broken (VPN
	// account banned, daemon deadlocked, network partition). Exit so
	// systemd Restart=always respawns this binary INSIDE the same
	// container — that re-runs Login + Connect from scratch, often
	// clearing a wedged provider daemon. Doing it this way (not
	// kubelet liveness 503) preserves /var/log/journal across the
	// recovery and keeps the kubelet-visible restart count quiet.
	wedgeThreshold := time.Duration(getEnvInt(envWedgeGuardSec, defaultWedgeGuardSec)) * time.Second
	go runWedgeGuard(ctx, state, wedgeThreshold)

	// Self-recycle: after a jittered max lifetime and/or a max rotation
	// count, gracefully drain and exit the CONTAINER so kubelet recreates
	// it on the latest image (imagePullPolicy: Always) and freshest env —
	// new builds/config roll out without hand-restarting pods. 0/0 = off.
	// Rotation-count trigger: handled inside the rotator (recycle replaces
	// the next rotation). Time trigger: the runRecycler backstop below.
	recycleRotationLimit = getEnvInt(envRecycleAfterRot, 0)
	recycleAfter := time.Duration(getEnvInt(envRecycleAfterSec, 0)) * time.Second
	if recycleAfter > 0 {
		go runRecycler(ctx, state, drain, recycleAfter)
	}

	// Rotation is now exclusively driven by the crawler: each slot
	// tracks AIMD + per-tunnel 429s and, on sustained throttling,
	// POSTs /rotate directly to this pod via the headless-service
	// DNS. The triggerRotation handler below is the same in-process
	// flow that scheduled rotations use.
	_ = triggerRotation // referenced by /rotate handler in startServer

	rotationDesc := fmt.Sprintf("[%s..%s]", minRotation, maxRotation)
	if !rotationEnabled {
		rotationDesc = "disabled"
	}
	log.Printf("tundler-tunnel: holding tunnel; watchdog=%s rotation=%s wedge_guard=%s",
		watchdogInterval, rotationDesc, wedgeThreshold)

	// Hold the tunnel until SIGTERM. Future slices add the self-monitor
	// (Trigger C) and Layer 1+2 envoy drain hooks.
	<-ctx.Done()
	log.Printf("tundler-tunnel: shutting down")
	// Release the device slot client-side before exiting (fresh context —
	// ctx is the now-cancelled signal context).
	gracefulDisconnect()
}

// runWatchdog observes the CONNECT proxy's actual dial outcomes
// instead of asking the VPN daemon. The reasoning: the daemon's CLI
// (expressvpnctl, piactl, etc.) is exactly the channel that wedges
// on us, and asking a wedged daemon "are you connected?" is the
// pathology we built our way into. The proxy is in the same Go
// process — it knows whether real CONNECT requests through tun0 are
// currently delivering packets or not. That's the ground truth.
//
// Decision table the watchdog uses each tick:
//
//	state == Ready, dialSilent → no signal, do nothing
//	state == Ready, last dial succeeded → tunnel is fine, do nothing
//	state == Ready, ConsecutiveFailures >= threshold → tunnel suspect
//	                                                    → attempt reconnect
//	state == Failed → always attempt reconnect (with backoff)
//	other states (Booting / LoggingIn / Connecting / Draining /
//	              Rotating) → another code path owns the lifecycle,
//	                          stay out of the way
//
// The goroutine STAYS ALIVE across reconnect failures: a failed
// attempt sets state=Failed and sleeps with exponential backoff,
// then ticks back around. Truly unrecoverable wedges (the proxy can
// dial nothing, the daemon's CLI keeps timing out on Connect) are
// caught by runWedgeGuard, which exits the process after the wedge
// threshold; systemd then respawns the binary fresh, and if the new
// binary also can't initial-connect, failAndExit exits 2 and kubelet
// container-restarts the pod.
func runWatchdog(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, interval time.Duration, proxySrv *proxy.Server, baselineEgressIP string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	backoff := watchdogMinBackoff
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := state.Get()
			// Stay out of the way while some other code path drives
			// the connection. /rotate handlers, initial connect, and
			// in-flight rotations all transition through these.
			if current != StateReady && current != StateFailed {
				continue
			}
			if current == StateReady && tunnelLooksHealthy(proxySrv) {
				backoff = watchdogMinBackoff
				continue
			}
			h := proxySrv.RecentTunnelHealth()
			log.Printf("tundler-tunnel: watchdog reconnect attempt (state=%s, consecutiveDialFails=%d, lastDialAt=%s)",
				current, h.ConsecutiveFailures, h.LastDialAt.Format(time.RFC3339))
			if err := connectTunnel(ctx, prov, state, providerName, excluded, baselineEgressIP); err != nil {
				log.Printf("tundler-tunnel: watchdog reconnect failed: %v (next retry in %s)",
					err, backoff)
				state.Set(StateFailed)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < watchdogMaxBackoff {
					backoff *= 2
					if backoff > watchdogMaxBackoff {
						backoff = watchdogMaxBackoff
					}
				}
				continue
			}
			backoff = watchdogMinBackoff
		}
	}
}

// tunnelLooksHealthy is the watchdog's "should I leave this alone?"
// predicate, based on what the in-process CONNECT proxy has actually
// observed on its upstream dials. Returns true iff:
//
//	- no dial has happened recently (within dialSilenceWindow) — no
//	  signal to act on; or
//	- the very latest dial succeeded — proof the tunnel is currently
//	  delivering packets; or
//	- consecutive failures are below dialFailureThreshold — a few
//	  failures could just be unreachable hosts, not a tunnel problem.
//
// Returns false (i.e. "go ahead, try to reconnect") only when there's
// recent traffic AND a sustained failure pattern that the proxy
// observed end-to-end.
func tunnelLooksHealthy(proxySrv *proxy.Server) bool {
	h := proxySrv.RecentTunnelHealth()
	if h.LastDialAt.IsZero() || time.Since(h.LastDialAt) > dialSilenceWindow {
		return true
	}
	if h.LastDialSucceeded {
		return true
	}
	return h.ConsecutiveFailures < dialFailureThreshold
}

// runWedgeGuard exits the process when state stays continuously NOT
// Ready for longer than threshold. Designed to catch genuine wedges
// (account banned, deadlocked provider daemon, network partition)
// that the resilient watchdog cannot recover from on its own.
//
// Exiting (vs the old kubelet /livez 503 → SIGKILL) keeps the failure
// inside the container: systemd's Restart=always respawns the binary
// fresh, /var/log/journal survives so we can post-mortem the wedge,
// and kubelet's restart count stays clean.
//
// nonReadySince is reset every time state re-enters Ready, so a
// flaky-but-recovering watchdog never trips the guard.
func runWedgeGuard(ctx context.Context, state *StateTracker, threshold time.Duration) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var nonReadySince time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if state.Get() == StateReady {
				if !nonReadySince.IsZero() {
					log.Printf("tundler-tunnel: wedge guard cleared after %s",
						time.Since(nonReadySince).Round(time.Second))
					nonReadySince = time.Time{}
				}
				continue
			}
			if nonReadySince.IsZero() {
				nonReadySince = time.Now()
				continue
			}
			elapsed := time.Since(nonReadySince)
			if elapsed > threshold {
				log.Printf("tundler-tunnel: wedge guard tripped — state=%s for %s (> %s); exiting for systemd respawn",
					state.Get(), elapsed.Round(time.Second), threshold)
				// Drop any half-up tunnel so the respawn doesn't briefly
				// overlap a second session on the account.
				gracefulDisconnect()
				os.Exit(1)
			}
		}
	}
}

// exitUnrecoverable is the exit code that tells systemd "don't restart
// this binary — escalate to kubelet via /livez ECONNREFUSED." Paired
// with `RestartPreventExitStatus=2` in tundler-tunnel.service. Used by
// failAndExit, called from the initial-Login / initial-Connect path
// when the provider daemon (expressvpnd / piad / openvpn) is wedged
// in a way the in-binary watchdog can't recover from. Triggering a
// container restart (instead of the systemd-respawn loop that ran
// 437× on tundler-tunnel-expressvpn-1 over 9.5 h) gets us back to
// Ready in ~30 s (one livenessProbe failureThreshold cycle).
//
// Distinct from the wedge guard's `os.Exit(1)`, which DOES want a
// systemd respawn — the runtime "was Ready, lost it" case is often
// just stale Go state and a fresh process inside the same container
// can recover. If that respawn ALSO hits a daemon wedge, its
// failAndExit will exit 2 and escalate from there.
const exitUnrecoverable = 2

// failAndExit is the unrecoverable-startup-error path: initial Login
// or initial Connect could not establish a baseline tunnel. We exit
// with exitUnrecoverable so systemd does NOT respawn (per
// RestartPreventExitStatus=2); kubelet then container-restarts the
// pod once livenessProbe sees /livez ECONNREFUSED.
func failAndExit(state *StateTracker) {
	state.Set(StateFailed)
	time.Sleep(2 * time.Second) // let an in-flight /status probe see Failed
	// If a tunnel (or just a login) was established before we gave up,
	// disconnect so the provider frees the device slot rather than aging
	// out a dangling session. No-op when nothing is connected.
	gracefulDisconnect()
	os.Exit(exitUnrecoverable)
}

func registryKeys() []string {
	keys := make([]string, 0, len(provider.Registry))
	for k := range provider.Registry {
		keys = append(keys, k)
	}
	return keys
}

// getEnvInt reads an integer env var; returns def if unset, fatals if
// set to a non-integer. Used for the small handful of numeric tuning
// knobs (jitter window, watchdog interval).
func getEnvInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		log.Fatalf("tundler-tunnel: %s=%q is not a non-negative integer", name, v)
	}
	return n
}

