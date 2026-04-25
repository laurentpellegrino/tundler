package manager

import (
	"context"
	"os"
	"time"

	"github.com/laurentpellegrino/tundler/internal/shared"
)

// Watchdog cadence and tolerances.
//
// `watchdogProbeTimeout` caps how long a single provider's status query
// may take before the tick counts it as a probe failure — short enough
// to detect a wedge promptly, long enough that a momentarily slow CLI
// (network blip during dial-in, daemon loading config) doesn't trip it.
//
// `watchdogInterval` × `watchdogWedgeTolerance` is the wall-clock
// budget before a wedged provider triggers a tundler exit. Set
// generously: the recovery is full container restart, so we'd rather
// tolerate a few minutes of slow provider than churn through restarts
// that cost their own re-login + tunnel re-establishment time.
const (
	watchdogInterval       = 30 * time.Second
	watchdogProbeTimeout   = 5 * time.Second
	watchdogWedgeTolerance = 10 // 10 × 30 s = 5 minutes
)

// StartWatchdog launches a background goroutine that periodically
// probes each registered provider's status CLI. After
// {@code watchdogWedgeTolerance} consecutive probe timeouts on the
// same provider — meaning that provider's daemon has been wedged for
// the full tolerance window — tundler calls os.Exit(1) so kubelet
// recreates the container with a clean set of daemons.
//
// Why this exists: kubelet's livenessProbe is now pointed at /livez,
// which only checks that tundler's HTTP server is responsive. That
// stops kubelet from SIGKILLing the container every time a single VPN
// CLI takes >5 s to respond — a recurring failure mode (expressvpnd
// CPU-spin, surfshark-vpn long-dial) that destroyed all login state on
// every flap. But /livez is too lax: tundler stays alive even when its
// providers are silently broken, leaving the crawler stuck on connect
// failures forever. This watchdog fills the gap by self-detecting
// sustained provider wedges without involving kubelet's probe path.
//
// The crawler's connectOrRelogin recovers the post-restart login
// state, so the only cost of an exit is a few seconds of tunnel
// downtime — preferable to silent indefinite degradation.
func (m *Manager) StartWatchdog(ctx context.Context) {
	go m.runWatchdog(ctx)
}

func (m *Manager) runWatchdog(ctx context.Context) {
	failures := make(map[string]int, len(m.providers))
	ticker := time.NewTicker(watchdogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for name, p := range m.providers {
				probeCtx, cancel := context.WithTimeout(ctx, watchdogProbeTimeout)
				_ = p.LoggedIn(probeCtx)
				wedged := probeCtx.Err() == context.DeadlineExceeded
				cancel()

				if wedged {
					failures[name]++
					shared.Debugf("[watchdog] %s probe timed out (%d/%d)",
						name, failures[name], watchdogWedgeTolerance)
					if failures[name] >= watchdogWedgeTolerance {
						shared.Debugf("[watchdog] %s wedged for %v, exiting tundler",
							name, watchdogInterval*time.Duration(failures[name]))
						os.Exit(1)
					}
					continue
				}
				if failures[name] > 0 {
					shared.Debugf("[watchdog] %s recovered after %d timeouts",
						name, failures[name])
				}
				failures[name] = 0
			}
		}
	}
}
