package main

import (
	"context"
	"fmt"
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

// runRotator fires a tunnel rotation every uniform random pick in
// [minInterval, maxInterval], picking a fresh allowed location each
// time. Lifecycle: Ready → Draining → Rotating → Ready / Failed.
//
// The initial sleep before the first rotation is also sampled from
// the same window, so a fleet of N pods that boot together is spread
// across the full window from the first rotation onward — no
// synchronized stampede min-window-seconds later either.
//
// Skipped if state != Ready/Failed (e.g., a previous rotation is in
// flight, or the watchdog is reconnecting).
func runRotator(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, minInterval, maxInterval time.Duration, drain drainController, baselineEgressIP string) {
	initialOffset := pickRotationInterval(minInterval, maxInterval)
	log.Printf("tundler-tunnel: rotator armed; first rotation in %s (then every random %s..%s)",
		initialOffset.Round(time.Second), minInterval, maxInterval)

	timer := time.NewTimer(initialOffset)
	defer timer.Stop()
	state.RecordNextRotation(time.Now().Add(initialOffset))

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			rotateIfReady(ctx, prov, state, providerName, excluded, drain, baselineEgressIP)
			next := pickRotationInterval(minInterval, maxInterval)
			log.Printf("tundler-tunnel: next rotation in %s", next.Round(time.Second))
			timer.Reset(next)
			state.RecordNextRotation(time.Now().Add(next))
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
func rotateIfReady(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, drain drainController, baselineEgressIP string) {
	rotateIfReadyWithDeps(ctx, prov, state, providerName, excluded,
		getEnvInt(envRotationRetryMax, defaultRotationRetryMax), time.Sleep, drain, baselineEgressIP)
}

// rotateIfReadyWithDeps is the testable form of rotateIfReady — exposes
// maxAttempts + sleep so tests can drive deterministic behavior without
// reading env vars or waiting for real backoffs.
func rotateIfReadyWithDeps(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, maxAttempts int, sleep func(time.Duration), drain drainController, baselineEgressIP string) {
	// Accept Failed too: the watchdog usually drives recovery, but the
	// scheduled rotator is a periodic backup path for the rare case
	// where the watchdog is wedged (e.g., a CPU-pinned thread).
	current := state.Get()
	if current != StateReady && current != StateFailed {
		log.Printf("tundler-tunnel: rotator skipping; state=%s (not Ready/Failed)", current)
		return
	}

	// Recycle instead of rotating once this pod has done its allotted
	// rotations: a fresh container gives a new exit IP AND picks up the
	// latest image + freshest env. So the (limit+1)th rotation becomes a
	// graceful container recycle rather than another in-place reconnect.
	if recycleRotationLimit > 0 && state.Snapshot().RotationCountTotal >= recycleRotationLimit {
		recycleContainer(ctx, state, drain,
			fmt.Sprintf("completed %d rotations", recycleRotationLimit))
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

	if err := connectWithRetry(ctx, prov, state, providerName, excluded, maxAttempts, sleep, baselineEgressIP); err != nil {
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

// pickRotationInterval returns a uniform random duration in [min, max].
// When min == max it returns exactly that value (no rand call). When
// max < min the caller should have already clamped them (main does);
// this helper still returns min defensively rather than panic on a
// negative argument to rand.Int64N.
func pickRotationInterval(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	span := int64(max - min)
	return min + time.Duration(rand.Int64N(span))
}
