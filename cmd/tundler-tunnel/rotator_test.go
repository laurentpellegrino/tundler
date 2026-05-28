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

	rotateIfReady(context.Background(), fp, st, "fake", nil, nil, "")

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
			rotateIfReady(context.Background(), fp, st, "fake", nil, nil, "")
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

	rotateIfReady(context.Background(), fp, st, "fake", nil, nil, "")

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

// TestPickRotationInterval_SpreadAcrossWindow: with min=60s, max=240s
// (the same 1:2 ratio as the production 2h..4h default), picks should
// span the full window with a stddev close to the theoretical
// (max-min)/√12. Proves a fleet of N pods that boot at the same instant
// will produce a true random spread of first-rotation times rather
// than clustering near one edge of the window.
func TestPickRotationInterval_SpreadAcrossWindow(t *testing.T) {
	const (
		n         = 200
		min       = 60 * time.Second
		max       = 240 * time.Second
		minStdDev = 36.0 // ~70% of theoretical (240-60)/√12 ≈ 51.96
	)
	samples := make([]float64, n)
	for i := range samples {
		samples[i] = pickRotationInterval(min, max).Seconds()
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
		t.Errorf("pickRotationInterval stddev = %.2fs over %d samples, want > %.1fs", stdDev, n, minStdDev)
	}
}

// TestPickRotationInterval_StaysWithinBounds: every pick is in
// [min, max). Prevents regressions that would let rotation drift
// outside the operator-configured window.
func TestPickRotationInterval_StaysWithinBounds(t *testing.T) {
	const (
		min = 60 * time.Second
		max = 240 * time.Second
	)
	for i := 0; i < 1000; i++ {
		got := pickRotationInterval(min, max)
		if got < min || got >= max {
			t.Fatalf("pickRotationInterval(%s, %s) = %s, want in [%s, %s)", min, max, got, min, max)
		}
	}
}

// TestPickRotationInterval_EqualBoundsReturnsExact: when an operator
// pins min == max for a fixed cadence, the helper must not divide by
// zero (rand.Int64N(0) would panic) and must return exactly that value.
func TestPickRotationInterval_EqualBoundsReturnsExact(t *testing.T) {
	const fixed = 60 * time.Second
	for i := 0; i < 100; i++ {
		if got := pickRotationInterval(fixed, fixed); got != fixed {
			t.Fatalf("pickRotationInterval(%s, %s) = %s, want exactly %s", fixed, fixed, got, fixed)
		}
	}
}
