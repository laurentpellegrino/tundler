package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
)

// scriptedProvider lets a test pre-program Connect outcomes per attempt
// (true = succeed, false = fail). Used to drive deterministic retry
// scenarios without time-based flakiness.
type scriptedProvider struct {
	locations []string

	mu             sync.Mutex
	attempt        int
	connectOutcomes []bool   // index by attempt-1: true=success, false=fail
	callsByLocation map[string]int
	exitIPs         []string // exit IP per attempt
}

func newScriptedProvider(locations []string, outcomes []bool, ips []string) *scriptedProvider {
	return &scriptedProvider{
		locations:       locations,
		connectOutcomes: outcomes,
		callsByLocation: map[string]int{},
		exitIPs:         ips,
	}
}

func (s *scriptedProvider) Connect(_ context.Context, location string) provider.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempt++
	s.callsByLocation[location]++
	i := s.attempt - 1
	if i >= len(s.connectOutcomes) {
		return provider.Status{Connected: false}
	}
	ok := s.connectOutcomes[i]
	ip := ""
	if i < len(s.exitIPs) {
		ip = s.exitIPs[i]
	}
	return provider.Status{Connected: ok, IP: ip, Location: location}
}

func (s *scriptedProvider) Locations(_ context.Context) []string {
	return s.locations
}

func (s *scriptedProvider) ActiveLocation(_ context.Context) string  { return "" }
func (s *scriptedProvider) Connected(_ context.Context) bool          { return false }
func (s *scriptedProvider) Disconnect(_ context.Context) error        { return nil }
func (s *scriptedProvider) LoggedIn(_ context.Context) bool           { return true }
func (s *scriptedProvider) Login(_ context.Context) error             { return nil }
func (s *scriptedProvider) Logout(_ context.Context) error            { return nil }
func (s *scriptedProvider) Status(_ context.Context) provider.Status  { return provider.Status{} }
func (s *scriptedProvider) Version(_ context.Context) (string, error) { return "scripted", nil }

func (s *scriptedProvider) attemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempt
}

// noSleep is a sleep func that records the durations passed (so tests
// can assert backoff progression) but doesn't actually wait.
type noSleep struct {
	mu    sync.Mutex
	calls []time.Duration
}

func (n *noSleep) sleep(d time.Duration) {
	n.mu.Lock()
	n.calls = append(n.calls, d)
	n.mu.Unlock()
}

func (n *noSleep) durations() []time.Duration {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]time.Duration, len(n.calls))
	copy(out, n.calls)
	return out
}

// TestConnectWithRetry_SucceedsOnSecondAttempt: attempt 1 fails, attempt
// 2 succeeds → state Ready, one backoff slept (1s), 2 distinct locations
// tried (recentlyFailed excluded the first).
func TestConnectWithRetry_SucceedsOnSecondAttempt(t *testing.T) {
	sp := newScriptedProvider(
		[]string{"USA", "UK", "Germany"},
		[]bool{false, true},      // attempt 1 fails, attempt 2 succeeds
		[]string{"", "2.2.2.2"},  // exit IPs (empty when fail, set when success)
	)
	st := NewStateTracker("scripted")
	ns := &noSleep{}

	err := connectWithRetry(context.Background(), sp, st, "scripted", nil, 3, ns.sleep)
	if err != nil {
		t.Fatalf("connectWithRetry: %v", err)
	}
	if st.Get() != StateReady {
		t.Errorf("state=%s, want Ready", st.Get())
	}
	if got := sp.attemptCount(); got != 2 {
		t.Errorf("Connect called %d times, want 2", got)
	}
	if got := ns.durations(); len(got) != 1 || got[0] != 1*time.Second {
		t.Errorf("backoffs=%v, want [1s]", got)
	}
	// Two distinct locations tried (the failing one shouldn't be retried).
	if len(sp.callsByLocation) != 2 {
		t.Errorf("distinct locations=%d, want 2 (recentlyFailed excludes the failed one)", len(sp.callsByLocation))
	}
}

// TestConnectWithRetry_ExhaustsAllAttempts: every attempt fails → returns
// errRotationExhausted; state stays at Connecting (caller sets Failed
// after the helper returns).
func TestConnectWithRetry_ExhaustsAllAttempts(t *testing.T) {
	sp := newScriptedProvider(
		[]string{"USA", "UK", "Germany", "Switzerland"},
		[]bool{false, false, false}, // all 3 attempts fail
		[]string{"", "", ""},
	)
	st := NewStateTracker("scripted")
	ns := &noSleep{}

	err := connectWithRetry(context.Background(), sp, st, "scripted", nil, 3, ns.sleep)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errRotationExhausted) {
		t.Errorf("err=%v, want errRotationExhausted", err)
	}
	if got := sp.attemptCount(); got != 3 {
		t.Errorf("Connect called %d times, want 3", got)
	}
	// 3 distinct locations across the 3 attempts.
	if len(sp.callsByLocation) != 3 {
		t.Errorf("distinct locations=%d, want 3", len(sp.callsByLocation))
	}
	// Backoffs after attempts 1 and 2 (not after the final failed attempt 3).
	durations := ns.durations()
	if len(durations) != 2 || durations[0] != 1*time.Second || durations[1] != 2*time.Second {
		t.Errorf("backoffs=%v, want [1s, 2s]", durations)
	}
}

// TestConnectWithRetry_LocationPoolExhausted: only 2 allowed locations,
// both fail → returns errNoAllowedLocations on attempt 3 (no more
// locations to pick).
func TestConnectWithRetry_LocationPoolExhausted(t *testing.T) {
	sp := newScriptedProvider(
		[]string{"USA", "UK"},
		[]bool{false, false},
		[]string{"", ""},
	)
	st := NewStateTracker("scripted")
	ns := &noSleep{}

	err := connectWithRetry(context.Background(), sp, st, "scripted", nil, 3, ns.sleep)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errNoAllowedLocations) {
		t.Errorf("err=%v, want errNoAllowedLocations (location pool empty)", err)
	}
	// Only 2 Connect calls (the 3rd attempt couldn't pick a location).
	if got := sp.attemptCount(); got != 2 {
		t.Errorf("Connect called %d times, want 2", got)
	}
}

// TestRotateIfReadyWithDeps_FailureRetriesThenSurrenders: the rotator
// drives connectWithRetry; after all retries fail, state is Failed and
// last_rotation.outcome="failed".
func TestRotateIfReadyWithDeps_FailureRetriesThenSurrenders(t *testing.T) {
	sp := newScriptedProvider(
		[]string{"USA", "UK", "Germany"},
		[]bool{false, false, false},
		[]string{"", "", ""},
	)
	st := NewStateTracker("scripted")
	st.RecordTunnelUp("USA", "1.1.1.1") // pretend we were on USA
	st.Set(StateReady)

	ns := &noSleep{}
	rotateIfReadyWithDeps(context.Background(), sp, st, "scripted", nil, 3, ns.sleep)

	if st.Get() != StateFailed {
		t.Errorf("state=%s after exhausted retries, want Failed", st.Get())
	}
	snap := st.Snapshot()
	if snap.LastRotation == nil || snap.LastRotation.Outcome != "failed" {
		t.Errorf("last_rotation=%v, want outcome=failed", snap.LastRotation)
	}
	if snap.RotationCountTotal != 1 {
		t.Errorf("rotation_count_total=%d, want 1 (failed rotation still counts)", snap.RotationCountTotal)
	}
}

// TestRotateIfReadyWithDeps_RecoversOnSecondAttempt: rotation attempt 1
// fails, attempt 2 succeeds → state Ready, new exit IP recorded.
func TestRotateIfReadyWithDeps_RecoversOnSecondAttempt(t *testing.T) {
	sp := newScriptedProvider(
		[]string{"USA", "UK", "Germany"},
		[]bool{false, true},
		[]string{"", "9.9.9.9"},
	)
	st := NewStateTracker("scripted")
	st.RecordTunnelUp("USA", "1.1.1.1")
	st.Set(StateReady)

	ns := &noSleep{}
	rotateIfReadyWithDeps(context.Background(), sp, st, "scripted", nil, 3, ns.sleep)

	if st.Get() != StateReady {
		t.Errorf("state=%s, want Ready", st.Get())
	}
	snap := st.Snapshot()
	if snap.CurrentExitIP != "9.9.9.9" {
		t.Errorf("current_exit_ip=%q, want 9.9.9.9", snap.CurrentExitIP)
	}
	if snap.LastRotation == nil || snap.LastRotation.Outcome != "success" {
		t.Errorf("last_rotation=%v, want outcome=success", snap.LastRotation)
	}
	if snap.LastRotation.NewExitIP != "9.9.9.9" {
		t.Errorf("last_rotation.new_exit_ip=%q, want 9.9.9.9", snap.LastRotation.NewExitIP)
	}
}

// TestRetryBackoff_Schedule asserts the exponential schedule 1s, 2s, 4s,
// 8s, 16s, 16s (cap). Prevents a future regression where the cap is
// dropped accidentally.
func TestRetryBackoff_Schedule(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 16 * time.Second},
		{6, 16 * time.Second}, // capped
		{10, 16 * time.Second},
	}
	for _, c := range cases {
		if got := retryBackoff(c.attempt); got != c.want {
			t.Errorf("retryBackoff(%d) = %s, want %s", c.attempt, got, c.want)
		}
	}
}
