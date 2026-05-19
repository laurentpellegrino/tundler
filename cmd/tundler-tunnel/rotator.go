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
)

// runRotator fires a tunnel rotation every `minInterval ± jitter`, picking
// a fresh random allowed location each time. Mirrors the design-doc
// "Hourly random rotation" lifecycle (Ready → Draining → Rotating →
// Ready).
//
// The initial sleep before the first rotation is uniformly random in
// [0, minInterval) so a fleet of N pods that boot together don't all
// rotate at the same minute — the "Initial rotation timer is randomly
// offset 0-60 min at boot" property called out in the design doc.
//
// Skipped if state != Ready (e.g., a previous rotation is still in
// flight, or watchdog is reconnecting). Failed-rotation retry-with-
// different-location is a future slice; for now a single Connect failure
// transitions to Failed and the goroutine exits (liveness probe handles
// restart).
//
// Layer 1 (pod-side envoy graceful drain) and Layer 2 (in-flight wait)
// are stubbed for this slice — there's no pod-local envoy yet in the
// tundler-tunnel runtime. Those calls will be wired in when the xDS
// server + envoy container are added.
func runRotator(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, minInterval time.Duration) {
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
			rotateIfReady(ctx, prov, state, providerName, excluded)
			// Subsequent rotations: minInterval ± up to 10% jitter so
			// pods slowly desynchronize even if they boot at the same
			// moment. (Design doc says "every hour ± jitter".)
			next := jitterInterval(minInterval)
			timer.Reset(next)
		}
	}
}

// rotateIfReady runs one rotation cycle if the pod is currently in
// StateReady. Other states (Connecting, Draining, Rotating, Failed) mean
// some other code path is in charge of the connection — skip.
//
// On Connect failure, retries up to ROTATION_RETRY_MAX times with
// different locations (and exponential backoff between attempts) per the
// design-doc "Failed-rotation handling" section. If all attempts fail,
// surrenders to StateFailed; the liveness probe then triggers a k8s
// restart.
func rotateIfReady(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string) {
	rotateIfReadyWithDeps(ctx, prov, state, providerName, excluded,
		getEnvInt(envRotationRetryMax, defaultRotationRetryMax), time.Sleep)
}

// rotateIfReadyWithDeps is the testable form of rotateIfReady — exposes
// maxAttempts + sleep so tests can drive deterministic behavior without
// reading env vars or waiting for real backoffs.
func rotateIfReadyWithDeps(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, maxAttempts int, sleep func(time.Duration)) {
	if state.Get() != StateReady {
		log.Printf("tundler-tunnel: rotator skipping; state=%s (not Ready)", state.Get())
		return
	}

	started := time.Now()
	previousIP := state.SnapshotCurrentExitIP()

	// Draining: flip /readyz→503 immediately. In the future this is also
	// where Layer 1 (envoy admin /drain_listeners) + Layer 2 (poll
	// downstream_cx_active to zero) will live. Stub for now.
	state.Set(StateDraining)
	log.Printf("tundler-tunnel: rotation started (previous_exit_ip=%s)", previousIP)

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
