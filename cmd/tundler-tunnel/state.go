package main

import (
	"sync"
	"time"
)

// State is the tundler-tunnel pod's lifecycle position. Drives the
// /readyz HTTP probe and the /status JSON.
type State string

const (
	StateBooting    State = "Booting"    // process started, awaiting boot-login jitter
	StateLoggingIn  State = "LoggingIn"  // calling provider.Login()
	StateConnecting State = "Connecting" // calling provider.Connect() + waiting for tunnel up
	StateReady      State = "Ready"      // tunnel up; serving traffic
	StateDraining   State = "Draining"   // rotation start: /readyz→503; proxy drain in progress
	StateRotating   State = "Rotating"   // Disconnect done; reconnecting to new location
	StateFailed     State = "Failed"     // surrendered; watchdog will retry with backoff
)

// StateTracker is the source of truth for the /status JSON and the
// probe outcomes. All mutating accessors use a write lock; the JSON
// snapshotter uses a read lock. Safe for concurrent use from the HTTP
// handlers and the main goroutine.
//
// TunnelUpListener is called from RecordTunnelUp after the tracker's
// fields are updated. Used by main to wire proxy.Server.SetExitIP so
// the in-process CONNECT proxy emits the fresh exit IP in its
// response headers. Invoked outside the tracker's lock; safe for the
// listener to call back into the tracker (no deadlock).
type TunnelUpListener func(exitIP string)

type StateTracker struct {
	mu                    sync.RWMutex
	state                 State
	provider              string
	bootLoginJitterActual time.Duration
	loggedInAt            time.Time
	currentLocation       string
	currentExitIP         string
	tunnelConnectedAt     time.Time
	rotationCountTotal    int
	lastRotation          *RotationRecord
	tunnelUpListener      TunnelUpListener
	// lastReadyAt is the wall-clock time of the most recent transition
	// into StateReady. Used by /status for tunnel_age_seconds — the
	// wedge-guard goroutine owns the "stuck out of Ready" detection
	// (see runWedgeGuard in main.go), not /livez.
	lastReadyAt time.Time

	// nextRotationAt is the wall-clock time the rotator's timer is set to
	// fire. The rotator goroutine owns this — it stamps it when arming
	// the initial timer and after each Reset. Snapshot derives
	// next_rotation_in_seconds from it (clamped at 0). Zero value means
	// "rotation not yet scheduled", which /status reports as 0.
	nextRotationAt time.Time

	// authFailuresTotal counts every Login() failure observed since
	// process boot. Surfaced on /status so an aggregator (the crawler)
	// can sum across the fleet and page when a single provider's
	// counter spikes — that pattern is the canonical signature of
	// either a credentials drift (OpenBao out of sync with the
	// provider dashboard) or an account-level block (server-side
	// rejection of valid creds, e.g. the IPVanish lockout we hit on
	// 2026-05-28). Distinct from "Connect failures" because tunnel-
	// build failures are noisy (transient network), whereas auth
	// failures are nearly always operator-actionable.
	authFailuresTotal     int
	lastAuthFailureAt     time.Time
	lastAuthFailureReason string
}

// RotationRecord is the JSON shape under `last_rotation` in /status.
// Populated by RecordRotation after a rotation completes (success or
// surrender).
type RotationRecord struct {
	CompletedAt     string `json:"completed_at"`
	DurationSeconds int    `json:"duration_seconds"`
	Outcome         string `json:"outcome"` // "success" or "failed"
	PreviousExitIP  string `json:"previous_exit_ip,omitempty"`
	NewExitIP       string `json:"new_exit_ip,omitempty"`
}

// NewStateTracker initializes a tracker in StateBooting, parking the
// per-pod provider name so the /status JSON can echo it from t=0.
func NewStateTracker(provider string) *StateTracker {
	return &StateTracker{state: StateBooting, provider: provider}
}

func (s *StateTracker) Set(state State) {
	now := time.Now().UTC()
	s.mu.Lock()
	s.state = state
	if state == StateReady {
		if s.loggedInAt.IsZero() {
			s.loggedInAt = now
		}
		s.lastReadyAt = now
	}
	s.mu.Unlock()
}

func (s *StateTracker) Get() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// LastReadyAt is the wall-clock time the pod was last in StateReady.
// Returns the zero Time if it has never been Ready. Used by
// livezHandler to gate the "wedged for too long" check.
func (s *StateTracker) LastReadyAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastReadyAt
}

// RecordBootLoginJitter records the actual random duration slept before
// the first Login() call. Exposed in /status as
// boot_login_jitter_actual_seconds so operators can verify the fleet's
// jitter spread (Decision 9: per-provider configurable boot jitter).
func (s *StateTracker) RecordBootLoginJitter(d time.Duration) {
	s.mu.Lock()
	s.bootLoginJitterActual = d
	s.mu.Unlock()
}

// RecordTunnelUp captures the location + exit IP of a freshly-established
// tunnel and starts the tunnel_age_seconds clock. Called once Connect()
// reports the tunnel is up (Connecting → Ready transition).
//
// If a TunnelUpListener has been registered via SetTunnelUpListener, it's
// invoked with the new exit IP AFTER the tracker's internal state is
// updated (and outside the lock so the listener can call back into the
// tracker if needed). Used to fire xDS pushes on every tunnel-up.
func (s *StateTracker) RecordTunnelUp(location, exitIP string) {
	s.mu.Lock()
	s.currentLocation = location
	s.currentExitIP = exitIP
	s.tunnelConnectedAt = time.Now().UTC()
	listener := s.tunnelUpListener
	s.mu.Unlock()

	if listener != nil {
		listener(exitIP)
	}
}

// SetTunnelUpListener registers a callback fired on every RecordTunnelUp
// (initial connect, watchdog reconnect, rotation success). Production
// wires this to proxy.Server.SetExitIP so the in-process CONNECT proxy
// emits the fresh exit IP in its `x-tundler-exit-ip` response header.
//
// Safe to call concurrently with RecordTunnelUp. Setting nil clears the
// listener.
func (s *StateTracker) SetTunnelUpListener(fn TunnelUpListener) {
	s.mu.Lock()
	s.tunnelUpListener = fn
	s.mu.Unlock()
}

// SnapshotCurrentExitIP returns the exit IP recorded by the last
// RecordTunnelUp. Used by the rotator to capture previous_exit_ip
// before the new Connect overwrites it.
func (s *StateTracker) SnapshotCurrentExitIP() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentExitIP
}

// RecordRotation increments rotation_count_total and stamps the
// last_rotation field of the /status JSON. Called once a rotation
// completes (success or surrender). duration is the wall-clock time the
// rotation took (Draining → Ready or Failed).
func (s *StateTracker) RecordRotation(previousExitIP, newExitIP, outcome string, duration time.Duration) {
	s.mu.Lock()
	s.rotationCountTotal++
	s.lastRotation = &RotationRecord{
		CompletedAt:     time.Now().UTC().Format(time.RFC3339),
		DurationSeconds: int(duration.Round(time.Second).Seconds()),
		Outcome:         outcome,
		PreviousExitIP:  previousExitIP,
		NewExitIP:       newExitIP,
	}
	s.mu.Unlock()
}

// RecordNextRotation stamps the wall-clock time the rotator's timer is
// next set to fire. Called by the rotator goroutine when it arms the
// initial timer and after each Reset, so /status can report
// next_rotation_in_seconds.
func (s *StateTracker) RecordNextRotation(at time.Time) {
	s.mu.Lock()
	s.nextRotationAt = at
	s.mu.Unlock()
}

// Snapshot returns a copy of the tracker's state as the JSON-serializable
// shape /status emits.
func (s *StateTracker) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{
		State:                        s.state,
		Provider:                     s.provider,
		CurrentLocation:              s.currentLocation,
		CurrentExitIP:                s.currentExitIP,
		RotationCountTotal:           s.rotationCountTotal,
		LastRotation:                 s.lastRotation,
		BootLoginJitterActualSeconds: int(s.bootLoginJitterActual.Round(time.Second).Seconds()),
		AuthFailuresTotal:            s.authFailuresTotal,
		LastAuthFailureReason:        s.lastAuthFailureReason,
	}
	if !s.loggedInAt.IsZero() {
		snap.LoggedInAt = s.loggedInAt.Format(time.RFC3339)
	}
	if !s.tunnelConnectedAt.IsZero() {
		snap.TunnelAgeSeconds = int(time.Since(s.tunnelConnectedAt).Round(time.Second).Seconds())
	}
	if !s.lastAuthFailureAt.IsZero() {
		snap.LastAuthFailureAt = s.lastAuthFailureAt.Format(time.RFC3339)
	}
	if !s.nextRotationAt.IsZero() {
		if remaining := time.Until(s.nextRotationAt); remaining > 0 {
			snap.NextRotationInSeconds = int(remaining.Round(time.Second).Seconds())
		}
	}
	return snap
}

// RecordAuthFailure bumps the auth-failure counter and stamps a
// human-readable reason. Called from the Login-failure path; surfaces
// on /status as auth_failures_total / last_auth_failure_at /
// last_auth_failure_reason so an external aggregator can alert on
// per-provider spikes. Reason is truncated to 256 bytes to keep
// /status payloads bounded under pathological error strings.
func (s *StateTracker) RecordAuthFailure(reason string) {
	if len(reason) > 256 {
		reason = reason[:256]
	}
	s.mu.Lock()
	s.authFailuresTotal++
	s.lastAuthFailureAt = time.Now().UTC()
	s.lastAuthFailureReason = reason
	s.mu.Unlock()
}

// Snapshot is the JSON shape returned by /status. Field tags +
// omitempty rules: a slot consumer (crawler / leak detector) reads
// these to introspect the tunnel's current state.
type Snapshot struct {
	State                        State           `json:"state"`
	Provider                     string          `json:"provider"`
	CurrentLocation              string          `json:"current_location,omitempty"`
	CurrentExitIP                string          `json:"current_exit_ip,omitempty"`
	TunnelAgeSeconds             int             `json:"tunnel_age_seconds"`
	NextRotationInSeconds        int             `json:"next_rotation_in_seconds"`
	RotationCountTotal           int             `json:"rotation_count_total"`
	LoggedInAt                   string          `json:"logged_in_at,omitempty"`
	BootLoginJitterActualSeconds int             `json:"boot_login_jitter_actual_seconds"`
	LastRotation                 *RotationRecord `json:"last_rotation,omitempty"`
	// AuthFailuresTotal is the count of Login() rejections observed
	// since this process started. Always present (zero-valued at
	// boot) so an aggregator can poll without conditional branches.
	AuthFailuresTotal     int    `json:"auth_failures_total"`
	LastAuthFailureAt     string `json:"last_auth_failure_at,omitempty"`
	LastAuthFailureReason string `json:"last_auth_failure_reason,omitempty"`
}
