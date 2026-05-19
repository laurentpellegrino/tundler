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
	s.mu.Lock()
	s.state = state
	if state == StateReady && s.loggedInAt.IsZero() {
		s.loggedInAt = time.Now().UTC()
	}
	s.mu.Unlock()
}

func (s *StateTracker) Get() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
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
func (s *StateTracker) RecordTunnelUp(location, exitIP string) {
	s.mu.Lock()
	s.currentLocation = location
	s.currentExitIP = exitIP
	s.tunnelConnectedAt = time.Now().UTC()
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
