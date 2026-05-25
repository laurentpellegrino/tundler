package main

import (
	"context"
	"log"
	"math/rand/v2"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
)

const (
	envRotationRetryMax     = "ROTATION_RETRY_MAX"
	defaultRotationRetryMax = 3

	// drainWaitTimeout caps the in-flight-wait phase. If active CONNECT
	// tunnels haven't drained by then, rotation proceeds anyway —
	// survivors get reset when the upstream tunnel goes down.
	drainWaitTimeout = 30 * time.Second
)

// runRotator fires a tunnel rotation every `minInterval ± jitter`,
// picking a fresh random allowed location each time. Lifecycle:
// Ready → Draining → Rotating → Ready / Failed.
//
// The initial sleep before the first rotation is uniformly random in
// [0, minInterval) so a fleet of N pods that boot together don't all
// rotate at the same minute.
//
// Skipped if state != Ready/Failed (e.g., a previous rotation is in
// flight, or the watchdog is reconnecting).
func runRotator(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, minInterval time.Duration, drain drainController) {
	// Initial offset: random 0..minInterval. Prevents the entire fleet
	// from rotating at the same minute when they all boot together.
	initialOffset := time.Duration(rand.Int64N(int64(minInterval)))
	log.Printf("tundler-tunnel: rotator armed; first rotation in %s (then every ~%s)",
		initialOffset.Round(time.Second), minInterval)

	timer := time.NewTimer(initialOffset)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			rotateIfReady(ctx, prov, state, providerName, excluded, drain)
			// Subsequent rotations: minInterval ± up to 10% jitter so
			// pods slowly desynchronize even if they boot at the same
			// moment. (Design doc says "every hour ± jitter".)
			next := jitterInterval(minInterval)
			timer.Reset(next)
		}
	}
}

// rotateIfReady runs one rotation cycle if the pod is currently in
// StateReady or StateFailed. Other states (Connecting, Draining,
// Rotating) mean some other code path is in charge of the connection
// — skip.
//
// On Connect failure, retries up to ROTATION_RETRY_MAX times with
// different locations and exponential backoff between attempts. If
// all attempts fail, transitions to StateFailed; the watchdog will
// keep retrying from there with its own backoff.
//
// Production passes a proxyDrainController; tests use nil (skip the
// drain) or a fakeDrainController.
func rotateIfReady(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, drain drainController) {
	rotateIfReadyWithDeps(ctx, prov, state, providerName, excluded,
		getEnvInt(envRotationRetryMax, defaultRotationRetryMax), time.Sleep, drain)
}

// rotateIfReadyWithDeps is the testable form of rotateIfReady — exposes
// maxAttempts + sleep so tests can drive deterministic behavior without
// reading env vars or waiting for real backoffs.
func rotateIfReadyWithDeps(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, maxAttempts int, sleep func(time.Duration), drain drainController) {
	// Accept Failed too: the watchdog usually drives recovery, but the
	// scheduled rotator is a periodic backup path for the rare case
	// where the watchdog is wedged (e.g., a CPU-pinned thread).
	current := state.Get()
	if current != StateReady && current != StateFailed {
		log.Printf("tundler-tunnel: rotator skipping; state=%s (not Ready/Failed)", current)
		return
	}

	started := time.Now()
	previousIP := state.SnapshotCurrentExitIP()

	// Draining: flip /readyz→503 immediately so the crawler slot pinned
	// to this pod stops dispatching new CONNECTs, then wait for
	// in-flight tunnels to drain so we don't yank the VPN out from
	// under a live request.
	state.Set(StateDraining)
	log.Printf("tundler-tunnel: rotation started (previous_exit_ip=%s)", previousIP)

	if drain != nil {
		if err := drain.TriggerGracefulDrain(ctx); err != nil {
			log.Printf("tundler-tunnel: drain trigger failed (continuing): %v", err)
		}
		if err := drain.WaitForActiveConnectionsToDrain(ctx, drainWaitTimeout); err != nil {
			log.Printf("tundler-tunnel: drain wait: %v (proceeding to Disconnect)", err)
		}
	}

	// Rotating: disconnect, then reconnect with retry-with-different-
	// location. The connectWithRetry helper tracks recentlyFailed within
	// this rotation so the same broken location isn't retried twice.
	state.Set(StateRotating)
	if err := prov.Disconnect(ctx); err != nil {
		// Disconnect failures are surprisingly common when the network
		// is already flaky. Log + continue — the subsequent Connect
		// usually recovers (provider clients are idempotent).
		log.Printf("tundler-tunnel: rotation Disconnect failed (continuing to Connect): %v", err)
	}

	if err := connectWithRetry(ctx, prov, state, providerName, excluded, maxAttempts, sleep); err != nil {
		log.Printf("tundler-tunnel: rotation failed after retries: %v", err)
		state.RecordRotation(previousIP, "", "failed", time.Since(started))
		state.Set(StateFailed)
		return
	}

	newIP := state.SnapshotCurrentExitIP()
	state.RecordRotation(previousIP, newIP, "success", time.Since(started))
	log.Printf("tundler-tunnel: rotation complete (%s → %s) in %s",
		previousIP, newIP, time.Since(started).Round(time.Second))
}

// jitterInterval returns base ± up to 10% (uniform). Helps the fleet
// desynchronize over time even after a synchronized boot.
func jitterInterval(base time.Duration) time.Duration {
	pct := (rand.Float64() - 0.5) * 0.2 // [-0.1, +0.1]
	return base + time.Duration(float64(base)*pct)
}
