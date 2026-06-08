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
// [1s, 75s] (60s cap + 25% jitter) and never goes sub-second.
func TestBootConnectBackoff_CapsAndFloors(t *testing.T) {
	for attempt := 1; attempt <= 20; attempt++ {
		d := bootConnectBackoff(attempt)
		if d < time.Second {
			t.Fatalf("attempt %d: backoff %s < 1s floor", attempt, d)
		}
		if d > 75*time.Second {
			t.Fatalf("attempt %d: backoff %s exceeds 60s cap + jitter", attempt, d)
		}
	}
}
