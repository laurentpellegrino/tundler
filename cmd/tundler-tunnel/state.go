package main

import (
	"sync"
	"time"
)

// State is the tundler-tunnel pod's lifecycle position. Drives the /readyz
// and /livez HTTP probes and the /status JSON. Maps directly to the
// "state" field in the Tundler-hub /status response schema documented in
// architecture-tundler-fleet-controller.md (the per-pod schema).
type State string

const (
	StateBooting    State = "Booting"    // process started, awaiting boot-login jitter
	StateLoggingIn  State = "LoggingIn"  // calling provider.Login()
	StateConnecting State = "Connecting" // calling provider.Connect() + waiting for tunnel up
	StateReady      State = "Ready"      // tunnel up; serving traffic
	StateDraining   State = "Draining"   // rotation start: /readyz→503 + Layer 1 envoy drain in progress
	StateRotating   State = "Rotating"   // Disconnect done; reconnecting to new location
	StateFailed     State = "Failed"     // surrendered; /livez flips to 503 so k8s restarts
)

// StateTracker is the source of truth for the /status JSON and the probe
// outcomes. All mutating accessors use a write lock; the JSON snapshotter
// uses a read lock. Safe for concurrent use from the HTTP handlers and the
// main goroutine.
// TunnelUpListener is called from RecordTunnelUp after the tracker's
// fields are updated. Used by main to wire the xDS server's PushExitIP
// without coupling cmd/tundler-tunnel to the xds package directly.
// Invoked outside the tracker's lock; safe for the listener to call
// back into the tracker (no deadlock).
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
	// into StateReady. Used by /livez to distinguish "transiently not
	// Ready (rotating, briefly Failed)" — which is fine — from
	// "genuinely wedged" — which warrants a k8s restart. See livezHandler
	// and StateMaxNonReady. Zero value means "never been Ready"; the
	// boot path treats that as "still booting, give it time".
	lastReadyAt time.Time
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
// wires this to xds.Server.PushExitIP so the pod-local envoy gets a
// fresh snapshot with the updated x-tundler-exit-ip header.
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

// Snapshot returns a copy of the tracker's state as the JSON-serializable
// shape /status emits. next_rotation_in_seconds is not populated here —
// the rotator goroutine owns that knowledge; later slices may pipe it
// through if dashboards need it.
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
	}
	if !s.loggedInAt.IsZero() {
		snap.LoggedInAt = s.loggedInAt.Format(time.RFC3339)
	}
	if !s.tunnelConnectedAt.IsZero() {
		snap.TunnelAgeSeconds = int(time.Since(s.tunnelConnectedAt).Round(time.Second).Seconds())
	}
	return snap
}

// Snapshot is the JSON shape returned by /status. Field tags + omitempty
// rules match the schema documented in
// architecture-tundler-fleet-controller.md.
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
}
