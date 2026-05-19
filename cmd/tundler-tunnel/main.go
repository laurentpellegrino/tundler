// Command tundler-tunnel is the simplified single-provider tundler runtime
// that runs in each per-provider tunnel pod of the VPN-hub architecture.
// See docs/architecture-tundler-fleet-controller.md in ipregistry-crawl.
//
// Implemented slices so far:
//   - boot-login-jitter + Login() + idle (slice a)
//   - HTTP server on :4242 with /readyz, /livez, /status (slice a')
//   - Connect to random allowed location + record current_location/exit_ip (slice b'.1)
//   - Watchdog reconnect on unexpected tunnel drop (slice b'.2)
//   - Hourly random rotation timer (Ready → Draining → Rotating → Ready) (slice c'.1)
//   - Failed-rotation retry-with-different-location (ROTATION_RETRY_MAX) (slice c'.2)
//   - POST /rotate HTTP handler (consumed by tundler-fleet-controller) (slice d'.1)
//   - internal/xds SnapshotBuilder + gRPC Server on :18000 (slice e'.1 + e'.2)
//   - Self-monitor (Trigger C): sliding-window 429-rate → auto-rotate (slice f'.1)
//
// Future slices: Layer 1+2 envoy drain hooks (call envoy admin's
// /drain_listeners + poll downstream_cx_active), per-provider Dockerfile
// + CI matrix.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	_ "github.com/laurentpellegrino/tundler/internal/provider/register"
	"github.com/laurentpellegrino/tundler/internal/xds"
)

const (
	envProvider              = "TUNDLER_TUNNEL_PROVIDER"
	envBootLoginJitterSec    = "BOOT_LOGIN_JITTER_SECONDS"
	envExcludedLocations     = "EXCLUDED_LOCATIONS"
	envWatchdogIntervalSec   = "TUNNEL_WATCHDOG_INTERVAL_SECONDS"
	envMinRotationSec        = "MIN_ROTATION_SECONDS"
	envPodName               = "POD_NAME"               // downward API; → x-tundler-tunnel-id
	envNodeIP                = "TUNDLER_TUNNEL_NODE_IP" // from caller; → x-tundler-node-ip
	envSelfMonitorIntervalSec = "SELF_MONITOR_INTERVAL_SECONDS"
	envSelfMonitorWindowSamples = "SELF_MONITOR_WINDOW_SAMPLES"
	envSelfMonitorThresholdPct  = "SELF_MONITOR_THRESHOLD_PERCENT"
	defaultBootJitterSec     = 60
	defaultWatchdogIntervSec = 30
	defaultMinRotationSec    = 3600 // 1h, per design-doc "Hourly random rotation"

	xdsListenAddr   = "127.0.0.1:18000" // loopback-only per design-doc tunnel-pod envoy config
	envoyAdminURL   = "http://127.0.0.1:9901"
	dataListenPort  = 8484 // matches the bake-time envoy bootstrap
)

func main() {
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

	// Wire state + HTTP server up front so probes can see the pod's
	// lifecycle from t=0 (Booting → LoggingIn → Ready / Failed).
	state := NewStateTracker(providerName)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// /rotate handler invokes this closure in a goroutine; rotateIfReady
	// guards on state==Ready internally so this is safe to call even if
	// the hourly rotator timer is racing with an HTTP-driven rotation.
	excluded := parseExcludedLocations(os.Getenv(envExcludedLocations))
	triggerRotation := func() {
		rotateIfReady(ctx, prov, state, providerName, excluded)
	}

	// xDS server: serves envoy config (LDS+CDS+RDS) to the pod-local
	// envoy on loopback :18000. Started before login so envoy can
	// connect early; the initial snapshot has an empty x-tundler-exit-ip
	// header until the first tunnel-up's PushExitIP arrives.
	podName := os.Getenv(envPodName)
	if podName == "" {
		// Local-dev fallback. Real pods get POD_NAME via downward API.
		podName = "tundler-tunnel-local"
	}
	xdsServer, err := xds.NewServer(xds.PodInputs{
		PodName:        podName,
		NodeIP:         os.Getenv(envNodeIP),
		DataListenPort: dataListenPort,
	})
	if err != nil {
		log.Fatalf("tundler-tunnel: xDS server init: %v", err)
	}
	go func() {
		if err := xdsServer.Serve(ctx, xdsListenAddr); err != nil {
			log.Printf("tundler-tunnel: xDS server: %v", err) // not fatal; envoy will reconnect
		}
	}()

	// Each successful tunnel-up rebuilds the envoy snapshot with the
	// new exit IP and pushes it on the xDS stream. Envoy receives the
	// update within ~100ms — the x-tundler-exit-ip header flips on the
	// next response without an envoy restart.
	state.SetTunnelUpListener(func(exitIP string) {
		if err := xdsServer.PushExitIP(exitIP); err != nil {
			log.Printf("tundler-tunnel: xDS push (exit_ip=%s) failed: %v", exitIP, err)
		}
	})

	go func() {
		if err := startServer(ctx, state, triggerRotation); err != nil {
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
		// Initial-login failure handling: flip state to Failed (so /livez
		// returns 503 within the next probe period — k8s sees the failure
		// and CrashLoopBackOff kicks in), give probes a moment to pick up
		// the new state, then exit non-zero.
		log.Printf("tundler-tunnel: initial login failed for provider=%s: %v", providerName, err)
		failAndExit(state)
	}

	// Tunnel hold: pick a random allowed location (provider-filtered minus
	// EXCLUDED_LOCATIONS) and Connect. On success → Ready. On failure
	// surrender to Failed. `excluded` is captured in triggerRotation
	// above; reuse it here.
	if err := connectTunnel(ctx, prov, state, providerName, excluded); err != nil {
		log.Printf("tundler-tunnel: initial connect failed: %v", err)
		failAndExit(state)
	}

	// Start the watchdog: detects unexpected tunnel drops and reconnects
	// to a (possibly different) random allowed location. The design doc
	// says drops should reconnect WITHOUT a re-login (login is one-shot;
	// session token cached by the VPN client).
	watchdogInterval := time.Duration(getEnvInt(envWatchdogIntervalSec, defaultWatchdogIntervSec)) * time.Second
	go runWatchdog(ctx, prov, state, providerName, excluded, watchdogInterval)

	// Start the hourly rotator: every MIN_ROTATION_SECONDS (default 1h)
	// ± 10% jitter, pick a fresh random location and rotate. Initial
	// offset is uniformly random in [0, MIN_ROTATION_SECONDS) so a fleet
	// that boots together doesn't rotate in lockstep.
	minRotation := time.Duration(getEnvInt(envMinRotationSec, defaultMinRotationSec)) * time.Second
	go runRotator(ctx, prov, state, providerName, excluded, minRotation)

	// Self-monitor (Trigger C): poll envoy admin /stats; if our exit
	// IP's 429-rate exceeds the threshold over the window, rotate
	// proactively. Same RotateTrigger as /rotate so the underlying
	// rotation lifecycle is reused.
	mp := defaultMonitorParams()
	mp.interval = time.Duration(getEnvInt(envSelfMonitorIntervalSec, int(mp.interval.Seconds()))) * time.Second
	mp.windowSamples = getEnvInt(envSelfMonitorWindowSamples, mp.windowSamples)
	mp.threshold = float64(getEnvInt(envSelfMonitorThresholdPct, int(mp.threshold*100))) / 100.0
	go runSelfMonitor(ctx, fetchEnvoyStats(envoyAdminURL), state, triggerRotation, mp)

	log.Printf("tundler-tunnel: holding tunnel; watchdog=%s rotation=%s self-monitor=%s/window=%d/threshold=%.0f%%",
		watchdogInterval, minRotation, mp.interval, mp.windowSamples, mp.threshold*100)

	// Hold the tunnel until SIGTERM. Future slices add the self-monitor
	// (Trigger C) and Layer 1+2 envoy drain hooks.
	<-ctx.Done()
	log.Printf("tundler-tunnel: shutting down")
}

// runWatchdog periodically polls the provider's Connected() state. When it
// detects the tunnel is down while we believe ourselves Ready, it calls
// connectTunnel to reconnect to a (possibly different) random allowed
// location. Watchdog only acts when state==Ready — it stays out of the
// way during transitions managed by other code (Connecting, Draining,
// Rotating in future slices).
//
// On reconnect failure the watchdog flips state to Failed; /livez will
// pick up the change within one probe period and k8s CrashLoopBackOff
// restarts the pod (which re-runs Login + Connect from scratch with a
// fresh boot-login jitter).
func runWatchdog(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if state.Get() != StateReady {
				// Some other code path is managing the connection
				// (initial connect, future rotation logic). Stay out.
				continue
			}
			if prov.Connected(ctx) {
				continue
			}
			log.Printf("tundler-tunnel: watchdog detected tunnel down — reconnecting")
			if err := connectTunnel(ctx, prov, state, providerName, excluded); err != nil {
				log.Printf("tundler-tunnel: watchdog reconnect failed: %v", err)
				state.Set(StateFailed)
				// Don't os.Exit from a goroutine — let the liveness
				// probe pick up the Failed state and let k8s do the
				// restart. The probe period (10s with failureThreshold=3
				// = 30s) is the worst case before restart.
				return
			}
		}
	}
}

// failAndExit transitions the tracker to Failed (so /livez flips to 503 on
// the next probe period and k8s CrashLoopBackOff kicks in), gives probes a
// moment to pick up the new state, then exits non-zero. Mirrors the
// initial-login failure handling for any other unrecoverable startup
// error (connect timeout, no allowed location, etc.).
func failAndExit(state *StateTracker) {
	state.Set(StateFailed)
	time.Sleep(2 * time.Second) // one probe period margin
	os.Exit(1)
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
