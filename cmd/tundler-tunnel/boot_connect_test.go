package main

import (
	"context"
	"testing"
	"time"
)

// noBootBackoff drives connectInitialWithRetry with zero waits so tests run
// without real sleeps.
func noBootBackoff(int) time.Duration { return 0 }

// TestConnectInitialWithRetry_RetriesUntilSuccess verifies the boot connect
// keeps retrying in-process (no exit) and reaches Ready once a Connect
// finally succeeds — without ever re-logging-in (the loop never calls
// Login at all).
func TestConnectInitialWithRetry_RetriesUntilSuccess(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA"},
		connectIP: "1.2.3.4",
		connectOK: false, // first attempts fail
	}
	const flipAfter = 3 // flip succeeds the NEXT (4th) Connect
	attempts := 0
	fp.onConnect = func(string) {
		attempts++
		if attempts == flipAfter {
			fp.mu.Lock()
			fp.connectOK = true
			fp.mu.Unlock()
		}
	}

	st := NewStateTracker("fake")
	err := connectInitialWithRetry(context.Background(), fp, st, "fake", nil, "", noBootBackoff)
	if err != nil {
		t.Fatalf("connectInitialWithRetry: %v", err)
	}
	if st.Get() != StateReady {
		t.Errorf("state=%s, want Ready", st.Get())
	}
	if got, want := fp.callCount(), flipAfter+1; got != want {
		t.Errorf("Connect called %d times, want %d", got, want)
	}
}

// TestLoginInitialWithRetry_RetriesUntilSuccess verifies boot login keeps
// retrying IN-PROCESS (never exits) until a Login succeeds, and records an
// auth failure for each failed attempt. This is the fix for the 700+ restart
// crashloop: a throttled account's login timeout must NOT container-restart
// the pod (each restart = a fresh login that deepens the throttle).
func TestLoginInitialWithRetry_RetriesUntilSuccess(t *testing.T) {
	fp := &fakeProvider{locations: []string{"USA"}}
	fp.loginFails.Store(3) // first 3 Login() calls fail, 4th succeeds

	st := NewStateTracker("fake")
	if err := loginInitialWithRetry(context.Background(), fp, st, "fake", noBootBackoff); err != nil {
		t.Fatalf("loginInitialWithRetry: %v", err)
	}
	if got := fp.loginCalls.Load(); got != 4 {
		t.Errorf("Login called %d times, want 4", got)
	}
	if got := st.Snapshot().AuthFailuresTotal; got != 3 {
		t.Errorf("AuthFailuresTotal=%d, want 3 (one per failed attempt)", got)
	}
}

// TestLoginInitialWithRetry_StopsOnContextCancel verifies the loop returns
// (rather than spinning forever) when the pod is shut down mid-login.
func TestLoginInitialWithRetry_StopsOnContextCancel(t *testing.T) {
	fp := &fakeProvider{locations: []string{"USA"}}
	fp.loginFails.Store(1 << 30) // never succeeds
	ctx, cancel := context.WithCancel(context.Background())

	st := NewStateTracker("fake")
	done := make(chan error, 1)
	go func() {
		done <- loginInitialWithRetry(ctx, fp, st, "fake",
			func(int) time.Duration { return time.Millisecond })
	}()
	// Let a few attempts happen, then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a context-cancellation error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("loginInitialWithRetry did not return after ctx cancel")
	}
}

// TestConnectInitialWithRetry_StopsOnContextCancel verifies the loop exits
// (rather than spinning forever) when the pod is shutting down mid-connect.
func TestConnectInitialWithRetry_StopsOnContextCancel(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA"},
		connectOK: false, // never succeeds
	}
	ctx, cancel := context.WithCancel(context.Background())
	fp.onConnect = func(string) {
		if fp.callCount() >= 3 {
			cancel()
		}
	}

	st := NewStateTracker("fake")
	done := make(chan error, 1)
	go func() {
		done <- connectInitialWithRetry(ctx, fp, st, "fake", nil, "",
			func(int) time.Duration { return time.Millisecond })
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a context-cancellation error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connectInitialWithRetry did not return after ctx cancel")
	}
}

// TestBootConnectBackoff_CapsAndFloors checks the backoff stays within
// [1s, 375s] (5min cap + 25% jitter) and never goes sub-second.
func TestBootConnectBackoff_CapsAndFloors(t *testing.T) {
	for attempt := 1; attempt <= 20; attempt++ {
		d := bootConnectBackoff(attempt)
		if d < time.Second {
			t.Fatalf("attempt %d: backoff %s < 1s floor", attempt, d)
		}
		if d > 375*time.Second {
			t.Fatalf("attempt %d: backoff %s exceeds 5min cap + jitter", attempt, d)
		}
	}
	// A high attempt must approach the 5-min cap (≥ 300s − 25% jitter),
	// proving the account-saturation backoff actually spaces attempts out
	// rather than staying at the old 60s.
	if d := bootConnectBackoff(15); d < 225*time.Second {
		t.Fatalf("attempt 15: backoff %s did not reach the 5min cap band", d)
	}
}
