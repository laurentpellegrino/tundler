package main

import (
	"context"
	"testing"
)

// resetReloginThrottle clears the package-level throttle so each test starts
// from a clean slate (the throttle is process-global, like in production).
func resetReloginThrottle() { lastReloginUnix.Store(0) }

// REGRESSION GUARD: a daemon that loses its session mid-life must be
// re-logged-in by the reconnect path, not reconnect-looped forever. This is
// the gap that left expressvpn slots stuck at 0 rps ("Not logged in") until
// a manual pod restart.
func TestConnectTunnel_ReLoginsWhenSessionLostMidLife(t *testing.T) {
	resetReloginThrottle()
	defer resetReloginThrottle()

	f := &fakeProvider{locations: []string{"USA"}, connectIP: "1.2.3.4", connectOK: true}
	f.loggedOut.Store(true) // daemon logged out since boot
	st := NewStateTracker("fake")

	if err := connectTunnel(context.Background(), f, st, "fake", nil, ""); err != nil {
		t.Fatalf("connectTunnel: %v", err)
	}
	if got := f.loginCalls.Load(); got != 1 {
		t.Errorf("expected exactly 1 re-login, got %d", got)
	}
	if st.Get() != StateReady {
		t.Errorf("state=%s, want Ready (recovered)", st.Get())
	}
}

func TestConnectTunnel_NoReLoginWhenSessionValid(t *testing.T) {
	resetReloginThrottle()
	defer resetReloginThrottle()

	f := &fakeProvider{locations: []string{"USA"}, connectIP: "1.2.3.4", connectOK: true}
	// loggedOut defaults false → LoggedIn() true → no re-login.
	st := NewStateTracker("fake")

	if err := connectTunnel(context.Background(), f, st, "fake", nil, ""); err != nil {
		t.Fatalf("connectTunnel: %v", err)
	}
	if got := f.loginCalls.Load(); got != 0 {
		t.Errorf("re-login should NOT fire when already logged in, got %d calls", got)
	}
}

// The throttle must prevent a flapping session from storming the account.
func TestEnsureLoggedIn_Throttled(t *testing.T) {
	resetReloginThrottle()
	defer resetReloginThrottle()

	f := &fakeProvider{}
	f.loggedOut.Store(true)

	// First call re-logins (and the fake's Login sets loggedOut=false), so to
	// test the throttle we keep the daemon logged-out and call again quickly.
	if err := ensureLoggedIn(context.Background(), f, "fake"); err != nil {
		t.Fatalf("first ensureLoggedIn should succeed: %v", err)
	}
	f.loggedOut.Store(true) // session lost again, immediately
	err := ensureLoggedIn(context.Background(), f, "fake")
	if err == nil {
		t.Fatal("second re-login within the throttle window should be refused")
	}
	if got := f.loginCalls.Load(); got != 1 {
		t.Errorf("throttle should cap re-logins at 1 in the window, got %d", got)
	}
}
