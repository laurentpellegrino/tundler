package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
)

// fakeProvider implements provider.VPNProvider for tests. Connect/Connected
// behavior is scriptable via fields. Connect calls record (location, time)
// so tests can assert ordering and arguments.
type fakeProvider struct {
	locations []string

	mu        sync.Mutex
	connected atomic.Bool
	connectIP string                 // returned in Status.IP on next Connect
	connectOK bool                   // whether next Connect should succeed
	calls     []string               // record of Connect(location) calls
	onConnect func(location string)  // optional hook called from Connect

	noLocations bool // when true, Locations() returns nil to force pick-fail
}

func (f *fakeProvider) Locations(_ context.Context) []string {
	if f.noLocations {
		return nil
	}
	return f.locations
}

func (f *fakeProvider) Connect(_ context.Context, location string) provider.Status {
	f.mu.Lock()
	f.calls = append(f.calls, location)
	hook := f.onConnect
	ok := f.connectOK
	ip := f.connectIP
	f.mu.Unlock()
	if hook != nil {
		hook(location)
	}
	if !ok {
		return provider.Status{Connected: false}
	}
	f.connected.Store(true)
	return provider.Status{Connected: true, IP: ip, Location: location}
}

func (f *fakeProvider) Connected(_ context.Context) bool { return f.connected.Load() }
func (f *fakeProvider) ActiveLocation(_ context.Context) string {
	return ""
}
func (f *fakeProvider) Disconnect(_ context.Context) error {
	f.connected.Store(false)
	return nil
}
func (f *fakeProvider) LoggedIn(_ context.Context) bool          { return true }
func (f *fakeProvider) Login(_ context.Context) error            { return nil }
func (f *fakeProvider) Logout(_ context.Context) error           { return nil }
func (f *fakeProvider) Status(_ context.Context) provider.Status { return provider.Status{Connected: f.connected.Load()} }
func (f *fakeProvider) Version(_ context.Context) (string, error) {
	return "fake", nil
}

func (f *fakeProvider) drop() { f.connected.Store(false) }

func (f *fakeProvider) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// TestConnectTunnel_Success: connectTunnel records tunnel-up details and
// transitions to Ready when the provider returns Connected=true.
func TestConnectTunnel_Success(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA"},
		connectIP: "1.2.3.4",
		connectOK: true,
	}
	st := NewStateTracker("fake")
	err := connectTunnel(context.Background(), fp, st, "fake", nil)
	if err != nil {
		t.Fatalf("connectTunnel: %v", err)
	}
	if st.Get() != StateReady {
		t.Errorf("state=%s, want Ready", st.Get())
	}
	snap := st.Snapshot()
	if snap.CurrentLocation != "USA" {
		t.Errorf("current_location=%q, want USA", snap.CurrentLocation)
	}
	if snap.CurrentExitIP != "1.2.3.4" {
		t.Errorf("current_exit_ip=%q, want 1.2.3.4", snap.CurrentExitIP)
	}
}

// TestConnectTunnel_NoAllowedLocations: when every location is excluded,
// connectTunnel returns errNoAllowedLocations and leaves state at
// Connecting (caller decides Failed).
func TestConnectTunnel_NoAllowedLocations(t *testing.T) {
	fp := &fakeProvider{locations: []string{"Bahrain"}}
	st := NewStateTracker("fake")
	err := connectTunnel(context.Background(), fp, st, "fake", []string{"Bahrain"})
	if err == nil {
		t.Fatal("expected error from connectTunnel, got nil")
	}
	if !errors.Is(err, errNoAllowedLocations) {
		t.Errorf("err=%v, want errNoAllowedLocations", err)
	}
}

// TestConnectTunnel_ConnectFails: connectTunnel surfaces the failure when
// Connect returns Connected=false.
func TestConnectTunnel_ConnectFails(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA"},
		connectOK: false,
	}
	st := NewStateTracker("fake")
	err := connectTunnel(context.Background(), fp, st, "fake", nil)
	if err == nil {
		t.Fatal("expected connect to fail, got nil")
	}
	if !strings.Contains(err.Error(), "connect failed") {
		t.Errorf("err=%q, want substring 'connect failed'", err)
	}
}

// TestWatchdog_DetectsDropAndReconnects: the watchdog notices the
// provider went disconnected and triggers a reconnect that succeeds.
func TestWatchdog_DetectsDropAndReconnects(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA", "UK", "Germany"},
		connectIP: "5.6.7.8",
		connectOK: true,
	}
	st := NewStateTracker("fake")
	st.Set(StateReady)
	st.RecordTunnelUp("USA", "1.2.3.4")
	fp.connected.Store(true)

	// Drop the tunnel — watchdog should reconnect to one of the locations.
	fp.drop()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWatchdog(ctx, fp, st, "fake", nil, 20*time.Millisecond)
		close(done)
	}()
	// Wait until the watchdog has triggered at least one reconnect.
	deadline := time.After(150 * time.Millisecond)
	for fp.callCount() == 0 {
		select {
		case <-deadline:
			t.Fatalf("watchdog did not call Connect within 150ms (call count=%d)", fp.callCount())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	if st.Get() != StateReady {
		t.Errorf("state=%s after reconnect, want Ready", st.Get())
	}
	snap := st.Snapshot()
	if snap.CurrentExitIP != "5.6.7.8" {
		t.Errorf("current_exit_ip=%q, want 5.6.7.8 (the reconnected IP)", snap.CurrentExitIP)
	}
}

// TestWatchdog_SkipsWhenNotReady: when state != Ready, the watchdog must
// not call Connect — some other code path owns the connection lifecycle.
func TestWatchdog_SkipsWhenNotReady(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA"},
		connectOK: true,
	}
	st := NewStateTracker("fake")
	st.Set(StateConnecting) // simulate initial connect in progress
	fp.connected.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWatchdog(ctx, fp, st, "fake", nil, 20*time.Millisecond)
		close(done)
	}()
	<-done

	if got := fp.callCount(); got != 0 {
		t.Errorf("watchdog called Connect %d times, want 0 (state was Connecting)", got)
	}
}

// TestWatchdog_ReconnectFailureMarksFailed: if Connect returns
// !Connected during a reconnect, watchdog transitions to Failed and
// exits its loop (relying on the liveness probe to trigger restart).
func TestWatchdog_ReconnectFailureMarksFailed(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA"},
		connectOK: false, // reconnect will fail
	}
	st := NewStateTracker("fake")
	st.Set(StateReady)
	fp.connected.Store(false) // already down

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWatchdog(ctx, fp, st, "fake", nil, 10*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
		// watchdog returned — good (it should after marking Failed)
	case <-time.After(500 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("watchdog did not return after reconnect failure")
	}

	if st.Get() != StateFailed {
		t.Errorf("state=%s after reconnect failure, want Failed", st.Get())
	}
}
