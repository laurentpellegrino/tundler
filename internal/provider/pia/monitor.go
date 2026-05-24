package pia

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laurentpellegrino/tundler/internal/shared"
)

// piactl emits one of these strings on each connectionstate change.
// Documented set from `piactl monitor connectionstate`:
//
//	Disconnected | Connecting | Still Connecting | Connected |
//	Interrupted  | Reconnecting | Still Reconnecting |
//	Disconnecting To Reconnect | Disconnecting
//
// We treat "Connected" as the only state that counts as connected. All
// other values are "not connected" — including the various transient
// reconnecting states. The pre-monitor Connected() implementation
// returned true for anything that didn't contain "disconnected", which
// counted "Unknown" / "Connecting" as connected and burned Connect()
// time chasing an IP that wasn't ready yet.
const stateConnected = "Connected"

// monitor wraps two long-lived `piactl monitor <type>` subprocesses
// (one for connectionstate, one for vpnip) and exposes the latest
// values via atomic reads. Replaces the ~3 piactl subprocess spawns
// per second that the polling Status()/Connect()/Connected() loop
// used to cause — each spawn paid the piactl Go-runtime startup cost
// (~50-200 ms) and serialized through pia-daemon's IPC socket, which
// is what produced the 5 s timeouts that wedged PIA pods on connect.
//
// Lifecycle:
//   - start() called once from Login() after the daemon is verified
//     responsive (so the monitor subprocesses don't crash trying to
//     connect to a not-yet-ready daemon).
//   - Each monitored value has a dedicated goroutine reading
//     stdout line-by-line.
//   - If a subprocess exits (EOF on stdout, signal, daemon restart),
//     the goroutine respawns with exponential backoff (1 s → 30 s).
//     Stale values are kept in the meantime so callers don't see a
//     spurious "not connected" during the brief respawn window.
//   - Fallback: if respawn fails more than monitorFailureThreshold
//     times within monitorFailureWindow, fallbackActive is set and
//     pia.Status() / pia.Connected() fall back to one-shot piactl
//     get calls. Prevents being stuck with stale state if `piactl
//     monitor` is broken on a specific PIA build.
type monitor struct {
	connectionState atomic.Value // string
	vpnIP           atomic.Value // string

	// fallback control — flipped to true if the monitor subprocesses
	// keep dying. Callers can read it via inFallback() and skip the
	// in-memory state, going back to one-shot piactl get.
	fallbackActive atomic.Bool

	// failure tracking for the fallback decision
	failureMu     sync.Mutex
	failureTimes  []time.Time
	failureWindow time.Duration
	failureLimit  int

	startOnce sync.Once
	stopCh    chan struct{}
}

const (
	monitorRespawnBaseDelay = 1 * time.Second
	monitorRespawnMaxDelay  = 30 * time.Second
	monitorFailureThreshold = 5
	monitorFailureWindow    = 5 * time.Minute
)

// globalMonitor is the process-wide PIA monitor. Single PIA instance
// per tundler-tunnel process, so one shared monitor is fine.
var globalMonitor = &monitor{
	stopCh:        make(chan struct{}),
	failureWindow: monitorFailureWindow,
	failureLimit:  monitorFailureThreshold,
}

func (m *monitor) start() {
	m.startOnce.Do(func() {
		m.connectionState.Store("")
		m.vpnIP.Store("")
		go m.streamLoop("connectionstate", &m.connectionState)
		go m.streamLoop("vpnip", &m.vpnIP)
		shared.Debugf("PIA monitor: started (connectionstate + vpnip)")
	})
}

// streamLoop runs one `piactl monitor <kind>` subprocess and forwards
// each line of output into the given atomic.Value. Respawns on exit.
func (m *monitor) streamLoop(kind string, target *atomic.Value) {
	delay := monitorRespawnBaseDelay
	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		ok := m.runOne(kind, target)
		if ok {
			// Reset backoff on a clean run (daemon was responsive
			// long enough to produce at least one value).
			delay = monitorRespawnBaseDelay
		} else {
			m.recordFailure()
			shared.Debugf("PIA monitor[%s]: subprocess exited; backoff %s", kind, delay)
		}

		select {
		case <-m.stopCh:
			return
		case <-time.After(delay):
		}
		delay *= 2
		if delay > monitorRespawnMaxDelay {
			delay = monitorRespawnMaxDelay
		}
	}
}

// runOne spawns one piactl monitor subprocess, reads its stdout until
// EOF, and updates target on each line. Returns true if the process
// produced at least one value before exiting (so the caller can reset
// backoff) — meaningful work was done.
func (m *monitor) runOne(kind string, target *atomic.Value) (gotAny bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "monitor", kind)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		shared.Debugf("PIA monitor[%s]: StdoutPipe error: %v", kind, err)
		return false
	}
	if err := cmd.Start(); err != nil {
		shared.Debugf("PIA monitor[%s]: start error: %v", kind, err)
		return false
	}

	go func() {
		<-m.stopCh
		cancel()
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		target.Store(line)
		gotAny = true
	}
	_ = cmd.Wait()
	return gotAny
}

// recordFailure tracks subprocess deaths within failureWindow and
// flips fallbackActive once failureLimit is exceeded. Once active,
// callers stop trusting the in-memory state and fall back to direct
// piactl get calls.
func (m *monitor) recordFailure() {
	m.failureMu.Lock()
	defer m.failureMu.Unlock()
	now := time.Now()
	cutoff := now.Add(-m.failureWindow)
	// Trim entries outside the window.
	keep := m.failureTimes[:0]
	for _, t := range m.failureTimes {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	m.failureTimes = append(keep, now)
	if len(m.failureTimes) >= m.failureLimit {
		if !m.fallbackActive.Load() {
			shared.Debugf("PIA monitor: %d failures in %s — falling back to one-shot piactl get",
				len(m.failureTimes), m.failureWindow)
		}
		m.fallbackActive.Store(true)
	}
}

// inFallback reports whether the monitor has given up and callers
// should use one-shot piactl get instead.
func (m *monitor) inFallback() bool { return m.fallbackActive.Load() }

// state returns the latest observed connectionstate, or "" if the
// monitor hasn't produced a value yet.
func (m *monitor) state() string {
	v, _ := m.connectionState.Load().(string)
	return v
}

// ip returns the latest observed VPN IP, or "" if not yet seen /
// not connected.
func (m *monitor) ip() string {
	v, _ := m.vpnIP.Load().(string)
	return v
}
