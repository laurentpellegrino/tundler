// Command tundler-tunnel is the simplified single-provider tundler runtime
// that runs in each per-provider tunnel pod of the VPN-hub architecture.
// See docs/architecture-tundler-fleet-controller.md in ipregistry-crawl.
//
// Implemented slices so far:
//   - boot-login-jitter + Login() + idle (slice a)
//   - HTTP server on :4242 with /readyz, /livez, /status (slice a')
//
// Future slices: connect tunnel + hold, hourly rotation, xDS server,
// /rotate endpoint, self-monitor (Trigger C).
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
)

const (
	envProvider           = "TUNDLER_TUNNEL_PROVIDER"
	envBootLoginJitterSec = "BOOT_LOGIN_JITTER_SECONDS"
	envExcludedLocations  = "EXCLUDED_LOCATIONS"
	defaultBootJitterSec  = 60
)

func main() {
	providerName := os.Getenv(envProvider)
	if providerName == "" {
		log.Fatalf("tundler-tunnel: %s must be set (e.g. expressvpn, nordvpn, pia)", envProvider)
	}

	jitterMax := defaultBootJitterSec
	if v := os.Getenv(envBootLoginJitterSec); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			log.Fatalf("tundler-tunnel: %s=%q is not a non-negative integer", envBootLoginJitterSec, v)
		}
		jitterMax = n
	}

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
	go func() {
		if err := startServer(ctx, state); err != nil {
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
	// EXCLUDED_LOCATIONS) and Connect. Watchdog reconnect is a future
	// slice; this one transitions to Ready on successful tunnel-up and
	// stays there until SIGTERM.
	state.Set(StateConnecting)
	excluded := parseExcludedLocations(os.Getenv(envExcludedLocations))
	available := prov.Locations(ctx)
	location, err := pickLocation(available, excluded)
	if err != nil {
		log.Printf("tundler-tunnel: no allowed location for provider=%s (got %d locations, %d excluded): %v",
			providerName, len(available), len(excluded), err)
		failAndExit(state)
	}
	log.Printf("tundler-tunnel: provider=%s connecting to location=%s", providerName, location)
	status := prov.Connect(ctx, location)
	if !status.Connected {
		log.Printf("tundler-tunnel: connect failed for provider=%s location=%s status=%+v",
			providerName, location, status)
		failAndExit(state)
	}
	state.RecordTunnelUp(location, status.IP)
	state.Set(StateReady)
	log.Printf("tundler-tunnel: provider=%s tunnel up location=%s exit_ip=%s — holding",
		providerName, location, status.IP)

	// Hold the tunnel until SIGTERM. Future slices add the hourly rotation
	// timer, watchdog reconnect, /rotate handler, and xDS pushes.
	<-ctx.Done()
	log.Printf("tundler-tunnel: shutting down")
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
