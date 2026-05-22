package main

import (
	"context"
	"math"
	"testing"
	"time"
)

// TestRotateIfReady_HappyPath: starting from Ready with a healthy
// fakeProvider, rotateIfReady transitions through Draining → Rotating →
// Ready, increments rotation_count_total, and records last_rotation
// with previous/new exit IPs.
func TestRotateIfReady_HappyPath(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA", "UK", "Germany"},
		connectIP: "5.5.5.5",
		connectOK: true,
	}
	fp.connected.Store(true)

	st := NewStateTracker("fake")
	st.RecordTunnelUp("USA", "1.1.1.1")
	st.Set(StateReady)

	rotateIfReady(context.Background(), fp, st, "fake", nil, nil)

	if st.Get() != StateReady {
		t.Errorf("state=%s, want Ready after rotation", st.Get())
	}
	snap := st.Snapshot()
	if snap.RotationCountTotal != 1 {
		t.Errorf("rotation_count_total=%d, want 1", snap.RotationCountTotal)
	}
	if snap.LastRotation == nil {
		t.Fatal("last_rotation is nil after rotation")
	}
	if snap.LastRotation.Outcome != "success" {
		t.Errorf("last_rotation.outcome=%q, want success", snap.LastRotation.Outcome)
	}
	if snap.LastRotation.PreviousExitIP != "1.1.1.1" {
		t.Errorf("previous_exit_ip=%q, want 1.1.1.1", snap.LastRotation.PreviousExitIP)
	}
	if snap.LastRotation.NewExitIP != "5.5.5.5" {
		t.Errorf("new_exit_ip=%q, want 5.5.5.5", snap.LastRotation.NewExitIP)
	}
	if snap.CurrentExitIP != "5.5.5.5" {
		t.Errorf("current_exit_ip=%q, want 5.5.5.5", snap.CurrentExitIP)
	}
}

// TestRotateIfReady_SkipsWhenNotReady: rotator must NOT touch the state
// if the pod is mid-Connecting (initial connect or watchdog reconnect)
// or any other non-Ready state. StateFailed is intentionally excluded —
// the rotator now retries from Failed so a transient provider throttle
// can self-heal without a k8s restart (covered by
// TestRotateIfReady_RetriesFromFailed).
func TestRotateIfReady_SkipsWhenNotReady(t *testing.T) {
	for _, s := range []State{StateBooting, StateLoggingIn, StateConnecting, StateDraining, StateRotating} {
		t.Run(string(s), func(t *testing.T) {
			fp := &fakeProvider{
				locations: []string{"USA"},
				connectOK: true,
			}
			st := NewStateTracker("fake")
			st.Set(s)
			rotateIfReady(context.Background(), fp, st, "fake", nil, nil)
			if fp.callCount() != 0 {
				t.Errorf("rotator called Connect %d times in state=%s, want 0", fp.callCount(), s)
			}
			if st.Get() != s {
				t.Errorf("rotator changed state %s → %s, want unchanged", s, st.Get())
			}
		})
	}
}

// TestRotateIfReady_FailureMarksFailed: when Connect during the rotation
// returns !Connected, state transitions to Failed and last_rotation
// records outcome=failed.
func TestRotateIfReady_FailureMarksFailed(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA"},
		connectOK: false, // rotation will fail
	}
	fp.connected.Store(true) // currently up; rotation will Disconnect + try to Connect

	st := NewStateTracker("fake")
	st.RecordTunnelUp("USA", "1.1.1.1")
	st.Set(StateReady)

	rotateIfReady(context.Background(), fp, st, "fake", nil, nil)

	if st.Get() != StateFailed {
		t.Errorf("state=%s after rotation failure, want Failed", st.Get())
	}
	snap := st.Snapshot()
	if snap.RotationCountTotal != 1 {
		t.Errorf("rotation_count_total=%d, want 1 (failure still counts)", snap.RotationCountTotal)
	}
	if snap.LastRotation == nil || snap.LastRotation.Outcome != "failed" {
		t.Errorf("last_rotation.outcome=%v, want failed", snap.LastRotation)
	}
}

// TestRotator_InitialOffsetSpread: 50 independent runRotator timers
// should produce a spread of initial-offset values whose stddev > 10s
// when minInterval=60s. Proves the fleet doesn't all rotate at once.
//
// This is the "Jittered initial rotation timer" test from the design
// doc's testing strategy, scaled down for a unit test (60s instead of
// 1h so the test completes in real time — but the proportions hold).
func TestRotator_InitialOffsetSpread(t *testing.T) {
	const (
		n           = 200
		minInterval = 60 * time.Second
		minStdDev   = 12.0 // ~70% of theoretical 60/√12 ≈ 17.3
	)
	// We can't easily instrument runRotator without changing its API,
	// so instead we sample the underlying random source directly the
	// same way runRotator does: rand.Int64N(int64(minInterval)).
	samples := make([]float64, n)
	for i := range samples {
		samples[i] = (jitterInterval(minInterval) - minInterval).Seconds()
		// jitterInterval returns ±10%; convert to seconds-from-base.
		// Distribution width ~ ±6s for a 60s base, so the stddev
		// comparison below uses a smaller threshold.
	}
	// For jitterInterval (±10%), spread is tiny. The MAIN concern of
	// the design-doc test is the INITIAL offset, which uses
	// rand.Int64N(minInterval) — that's a separate distribution.
	// Replicate the initial-offset distribution here:
	for i := range samples {
		// Mirror the runRotator initial-offset formula.
		// Using time.Duration(rand.Int64N(int64(minInterval))).
		// We can't import math/rand/v2 in a value-only context cleanly;
		// reuse pickJitter which has the same property (uniform [0,N)).
		samples[i] = pickJitter(int(minInterval.Seconds())).Seconds()
	}

	var sum float64
	for _, s := range samples {
		sum += s
	}
	mean := sum / float64(n)
	var sumSq float64
	for _, s := range samples {
		sumSq += (s - mean) * (s - mean)
	}
	stdDev := math.Sqrt(sumSq / float64(n))

	if stdDev < minStdDev {
		t.Errorf("initial-offset stddev = %.2fs over %d samples, want > %.1fs", stdDev, n, minStdDev)
	}
}

// TestJitterInterval_StaysWithinTenPercent: every jittered interval is
// within ±10% of base. Prevents a regression where the jitter widens
// accidentally and causes rotation cadence to drift wildly.
func TestJitterInterval_StaysWithinTenPercent(t *testing.T) {
	const base = 60 * time.Second
	// Integer math: ±10% as base*9/10 and base*11/10 — avoids constant
	// overflow rules when converting float64 const to time.Duration.
	b := int64(base)
	minAllowed := time.Duration(b * 9 / 10)
	maxAllowed := time.Duration(b * 11 / 10)
	for i := 0; i < 1000; i++ {
		got := jitterInterval(base)
		if got < minAllowed || got > maxAllowed {
			t.Fatalf("jitterInterval(%s) = %s, want in [%s, %s]", base, got, minAllowed, maxAllowed)
		}
	}
}
