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
	"github.com/laurentpellegrino/tundler/internal/proxy"
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

// withWatchdogBackoff overrides watchdogMinBackoff/watchdogMaxBackoff
// for the duration of a test and returns a restore func meant to be
// `defer`-ed. Lets tests exercise the retry loop in milliseconds
// instead of the production 5s/60s values.
func withWatchdogBackoff(min, max time.Duration) func() {
	prevMin, prevMax := watchdogMinBackoff, watchdogMaxBackoff
	watchdogMinBackoff, watchdogMaxBackoff = min, max
	return func() { watchdogMinBackoff, watchdogMaxBackoff = prevMin, prevMax }
}

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

// TestWatchdog_DetectsDropAndReconnects: when the proxy reports
// sustained upstream-dial failures, the watchdog triggers a reconnect.
// This is the slot path's primary signal — the proxy sees real
// CONNECT requests fail through tun0, the watchdog reacts.
func TestWatchdog_DetectsDropAndReconnects(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA", "UK", "Germany"},
		connectIP: "5.6.7.8",
		connectOK: true,
	}
	st := NewStateTracker("fake")
	st.Set(StateReady)
	st.RecordTunnelUp("USA", "1.2.3.4")

	// Drive the proxy's dial-failure counter past the threshold.
	proxySrv := proxy.New("", "", "")
	for i := 0; i < dialFailureThreshold+1; i++ {
		proxySrv.SeedDialOutcome(false)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWatchdog(ctx, fp, st, "fake", nil, 20*time.Millisecond, proxySrv)
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

// TestWatchdog_SkipsWhenNotReady: when state != Ready/Failed, the
// watchdog must not call Connect — some other code path owns the
// lifecycle.
func TestWatchdog_SkipsWhenNotReady(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA"},
		connectOK: true,
	}
	st := NewStateTracker("fake")
	st.Set(StateConnecting) // simulate initial connect in progress

	proxySrv := proxy.New("", "", "")
	// Even if the proxy were seeing failures, watchdog must not act
	// from Connecting state. Verify by seeding a high failure count.
	for i := 0; i < dialFailureThreshold+5; i++ {
		proxySrv.SeedDialOutcome(false)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWatchdog(ctx, fp, st, "fake", nil, 20*time.Millisecond, proxySrv)
		close(done)
	}()
	<-done

	if got := fp.callCount(); got != 0 {
		t.Errorf("watchdog called Connect %d times, want 0 (state was Connecting)", got)
	}
}

// TestWatchdog_StaysOutOfWayWhenProxyHealthy: even from StateReady,
// the watchdog must NOT act when the proxy's recent dials have all
// succeeded. This is the case that today's expressvpn-1-style daemon
// IPC wedge breaks if you ask the daemon — but the proxy knows the
// truth and tells us "tunnel is fine, don't touch it."
func TestWatchdog_StaysOutOfWayWhenProxyHealthy(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA"},
		connectOK: true,
	}
	st := NewStateTracker("fake")
	st.Set(StateReady)
	st.RecordTunnelUp("USA", "1.2.3.4")

	proxySrv := proxy.New("", "", "")
	proxySrv.SeedDialOutcome(true) // recent dial succeeded → all healthy

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWatchdog(ctx, fp, st, "fake", nil, 10*time.Millisecond, proxySrv)
		close(done)
	}()
	<-done

	if got := fp.callCount(); got != 0 {
		t.Errorf("watchdog called Connect %d times on a healthy proxy, want 0", got)
	}
}

// TestWatchdog_AbstainsWhenProxySilent: with no dial activity at all,
// the watchdog has no signal and must abstain from action even if
// state is Ready. The slot would observe any real tunnel breakage
// the moment it tries to dispatch a request.
func TestWatchdog_AbstainsWhenProxySilent(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA"},
		connectOK: true,
	}
	st := NewStateTracker("fake")
	st.Set(StateReady)
	st.RecordTunnelUp("USA", "1.2.3.4")

	// No SeedDialOutcome calls → LastDialAt is the zero value.
	proxySrv := proxy.New("", "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWatchdog(ctx, fp, st, "fake", nil, 10*time.Millisecond, proxySrv)
		close(done)
	}()
	<-done

	if got := fp.callCount(); got != 0 {
		t.Errorf("watchdog called Connect %d times on a silent proxy, want 0", got)
	}
}

// TestWatchdog_ReconnectFailureMarksFailedAndRetries: if Connect
// returns !Connected during a reconnect, watchdog transitions to
// Failed but STAYS ALIVE. The runtime trigger that ultimately decides
// to give up is runWedgeGuard (out-of-band, threshold-based) — the
// watchdog itself retries forever with exponential backoff. The old
// "watchdog exits on first failure" behavior would park the pod in
// Failed until the hourly rotator picked it up, which gave /livez time
// to flip and kubelet time to kill.
func TestWatchdog_ReconnectFailureMarksFailedAndRetries(t *testing.T) {
	// Dial backoff down so the test runs in ms, not seconds.
	defer withWatchdogBackoff(1*time.Millisecond, 5*time.Millisecond)()

	fp := &fakeProvider{
		locations: []string{"USA"},
		connectOK: false, // reconnect will fail
	}
	st := NewStateTracker("fake")
	st.Set(StateReady)

	proxySrv := proxy.New("", "", "")
	// Seed dial failures past threshold so the watchdog has reason to
	// act from StateReady; without this, tunnelLooksHealthy returns
	// true on a silent proxy and the watchdog correctly abstains.
	for i := 0; i < dialFailureThreshold+1; i++ {
		proxySrv.SeedDialOutcome(false)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWatchdog(ctx, fp, st, "fake", nil, 10*time.Millisecond, proxySrv)
		close(done)
	}()

	// Wait for the first reconnect attempt + Failed transition.
	deadline := time.After(500 * time.Millisecond)
	for fp.callCount() < 1 || st.Get() != StateFailed {
		select {
		case <-deadline:
			t.Fatalf("watchdog did not mark Failed within 500ms (calls=%d, state=%s)",
				fp.callCount(), st.Get())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Now the key assertion: goroutine must still be alive (no
	// premature return). Cancel the context and verify it exits
	// cleanly only because of cancellation.
	select {
	case <-done:
		t.Fatal("watchdog returned after first failure; expected it to keep retrying")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("watchdog did not exit after ctx cancel")
	}
}

// TestWatchdog_RecoversFromFailed: once the provider becomes Connected
// again, the watchdog (in retry-from-Failed mode) transitions the
// pod back to Ready. This is the path that replaces the old
// "watchdog gives up, hourly rotator picks up next tick" recovery —
// now recovery happens within a few backoff cycles.
func TestWatchdog_RecoversFromFailed(t *testing.T) {
	defer withWatchdogBackoff(1*time.Millisecond, 5*time.Millisecond)()

	fp := &fakeProvider{
		locations: []string{"USA"},
		connectIP: "1.1.1.1",
		connectOK: false, // start with failing reconnect
	}
	st := NewStateTracker("fake")
	st.Set(StateFailed)
	fp.connected.Store(false)

	proxySrv := proxy.New("", "", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWatchdog(ctx, fp, st, "fake", nil, 10*time.Millisecond, proxySrv)
		close(done)
	}()

	// Wait for at least one failed attempt to land us in Failed.
	deadline := time.After(500 * time.Millisecond)
	for fp.callCount() < 1 {
		select {
		case <-deadline:
			t.Fatalf("watchdog did not attempt reconnect (calls=%d)", fp.callCount())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Now flip the provider to "will connect successfully" and wait
	// for the watchdog to retry and reach Ready.
	fp.mu.Lock()
	fp.connectOK = true
	fp.mu.Unlock()
	fp.connected.Store(true)

	deadline = time.After(time.Second)
	for st.Get() != StateReady {
		select {
		case <-deadline:
			t.Fatalf("watchdog did not recover to Ready (state=%s, calls=%d)",
				st.Get(), fp.callCount())
		case <-time.After(20 * time.Millisecond):
		}
	}

	cancel()
	<-done
}
