package main

import (
	"context"
	"testing"
)

// resetShutdownState clears the package-level shutdown registration so each
// test starts from a clean slate (the production code registers once per
// process; tests register many times).
func resetShutdownState() {
	shutdownMu.Lock()
	shutdownProv = nil
	shutdownProvName = ""
	shutdownDone = false
	shutdownMu.Unlock()
}

func TestGracefulDisconnect_CallsDisconnectOnce(t *testing.T) {
	resetShutdownState()
	defer resetShutdownState()

	f := &fakeProvider{}
	f.connected.Store(true)
	registerShutdownDisconnect(f, "expressvpn")

	gracefulDisconnect()

	if got := f.disconnectCalls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 Disconnect call, got %d", got)
	}
	if f.connected.Load() {
		t.Fatalf("expected tunnel to be disconnected")
	}
}

func TestGracefulDisconnect_Idempotent(t *testing.T) {
	resetShutdownState()
	defer resetShutdownState()

	f := &fakeProvider{}
	registerShutdownDisconnect(f, "pia")

	// Several exit paths may race to disconnect (e.g. SIGTERM arriving while
	// failAndExit runs) — only the first should actually fire.
	gracefulDisconnect()
	gracefulDisconnect()
	gracefulDisconnect()

	if got := f.disconnectCalls.Load(); got != 1 {
		t.Fatalf("expected Disconnect to run at most once, got %d calls", got)
	}
}

func TestGracefulDisconnect_UsesFreshContext(t *testing.T) {
	resetShutdownState()
	defer resetShutdownState()

	f := &fakeProvider{}
	registerShutdownDisconnect(f, "nordvpn")

	// Simulate the SIGTERM path: the caller's context is already cancelled.
	// gracefulDisconnect must build its own live context so the daemon CLI
	// call isn't aborted instantly.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = ctx // gracefulDisconnect takes no ctx; this documents the scenario.

	gracefulDisconnect()

	if f.disconnectCtxErrd.Load() {
		t.Fatalf("Disconnect was handed a cancelled context; expected a fresh one")
	}
}

func TestGracefulDisconnect_NoProviderIsNoop(t *testing.T) {
	resetShutdownState()
	defer resetShutdownState()

	// Never registered (e.g. exit before the provider was resolved) — must
	// not panic.
	gracefulDisconnect()
}
