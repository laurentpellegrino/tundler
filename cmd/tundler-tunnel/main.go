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
		state.Set(StateFailed)
		time.Sleep(2 * time.Second) // one probe period margin
		os.Exit(1)
	}
	state.Set(StateReady)

	log.Printf("tundler-tunnel: provider=%s login successful — idling (tunnel hold not yet implemented)", providerName)
	// Future slices replace this with: connect tunnel, hold, rotate, etc.
	// For now, keep the process alive until SIGTERM so k8s doesn't see
	// "completed" + restart-loop.
	<-ctx.Done()
	log.Printf("tundler-tunnel: shutting down")
}

func registryKeys() []string {
	keys := make([]string, 0, len(provider.Registry))
	for k := range provider.Registry {
		keys = append(keys, k)
	}
	return keys
}
