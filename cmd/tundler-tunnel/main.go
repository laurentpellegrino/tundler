// Command tundler-tunnel is the simplified single-provider tundler runtime
// that runs in each per-provider tunnel pod of the VPN-hub architecture.
// See docs/architecture-tundler-fleet-controller.md in ipregistry-crawl.
//
// This is the initial slice: boot-login-jitter + Login() + idle.
// Future slices will add: tunnel hold, rotation, xDS server, /readyz, etc.
package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	_ "github.com/laurentpellegrino/tundler/internal/provider/register"
)

const (
	envProvider          = "TUNDLER_TUNNEL_PROVIDER"
	envBootLoginJitterSec = "BOOT_LOGIN_JITTER_SECONDS"
	defaultBootJitterSec = 60
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

	d := pickJitter(jitterMax)
	log.Printf("tundler-tunnel: provider=%s boot_login_jitter_actual=%s (max=%ds) — sleeping then logging in",
		providerName, d, jitterMax)
	time.Sleep(d)

	ctx := context.Background()
	if err := prov.Login(ctx); err != nil {
		// Initial-login failure handling (Decision Q-init-login): exit non-zero
		// and let k8s CrashLoopBackOff handle the restart cadence. Boot-login
		// jitter on each restart prevents fleet-wide retry storms.
		log.Printf("tundler-tunnel: initial login failed for provider=%s: %v", providerName, err)
		os.Exit(1)
	}

	log.Printf("tundler-tunnel: provider=%s login successful — idling (tunnel hold not yet implemented)", providerName)
	// Future slices replace this with: connect tunnel, hold, rotate, etc.
	// For now, keep the process alive so k8s doesn't see "completed" + restart-loop.
	select {}
}

func registryKeys() []string {
	keys := make([]string, 0, len(provider.Registry))
	for k := range provider.Registry {
		keys = append(keys, k)
	}
	return keys
}
