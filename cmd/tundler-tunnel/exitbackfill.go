package main

// Late exit-IP lookup.
//
// The exit IP comes from the provider CLI or, for providers whose CLI
// does not report it, from the post-connect egress probe. When that
// probe times out the contract soft-passes and the tunnel used to run
// with no exit IP until its next rotation, 6-8 h later: /status, the
// CONNECT proxy's exit header and the tunnel_up event all carried an
// empty exit, so clients could not tell exits apart and the event sinks
// never learnt that exit at all. Soft-passes are routine on a few
// providers (one pod logged 28 in 48 h).
//
// So when a tunnel comes up without an exit IP, a goroutine keeps
// probing in the background (15 s, 30 s, 60 s, then every 2 min) until
// it gets one, the tunnel is replaced, or the process stops.
//
// A tunnel whose probes keep failing is usually one that carries no
// traffic: the proxy watchdog cannot see that when the clients use
// another listener, and one such tunnel sat Ready for 38 min until its
// client gave up on it. So once the probes have failed for
// backfillGiveUpAfter, the tunnel is marked Failed and the watchdog
// replaces it. A probe that returns the pre-VPN baseline is a leak,
// not an exit, and fails the tunnel the same way.
//
// A connect without an exit is not a success at its location until the
// lookup finds one: counting it as one cleared the location's earlier
// failure, so a location whose tunnels never carried traffic was never
// held (one pod went back to the same dead location three times in 8 h).

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

var exitBackfillDelays = []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute}

// backfillGiveUpAfter is how long the probes may fail, counted in
// scheduled delays, before the tunnel is taken for dead: seven probes,
// the last one 9 min 45 s after the tunnel came up. Late answers do
// happen (one came at the sixth probe, 8 min 26 s in), so this stays
// above them.
const backfillGiveUpAfter = 9 * time.Minute

// probeExitForBackfill is the egress probe; tests replace it.
var probeExitForBackfill = probeContractEgressIP

// startExitIPBackfill looks the current tunnel's exit IP up in the
// background. Call it right after RecordTunnelUp with an empty exit.
func startExitIPBackfill(ctx context.Context, state *StateTracker, providerName, baseline string) {
	gen := state.TunnelUpCount()
	go backfillExitIP(ctx, state, gen, providerName, baseline, sleepCtx)
}

// sleepCtx waits d and reports false when ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func backfillExitIP(ctx context.Context, state *StateTracker, gen uint64, providerName, baseline string, wait func(context.Context, time.Duration) bool) {
	start := time.Now()
	var waited time.Duration
	for attempt := 0; ; attempt++ {
		d := exitBackfillDelays[min(attempt, len(exitBackfillDelays)-1)]
		if !wait(ctx, d) {
			return
		}
		waited += d
		if state.TunnelUpCount() != gen || state.SnapshotCurrentExitIP() != "" {
			return // replaced, or the exit became known another way
		}
		ip, err := probeExitForBackfill(ctx)
		if err != nil || ip == "" {
			if waited >= backfillGiveUpAfter {
				if err == nil {
					err = errors.New("empty answer")
				}
				failDeadTunnel(state, gen, providerName,
					fmt.Sprintf("no exit ip after %d probes over %s (last: %v)", attempt+1, waited, err))
				return
			}
			continue
		}
		if state.TunnelUpCount() != gen {
			return // a rotation started while the probe ran
		}
		if baseline != "" && ip == baseline {
			failDeadTunnel(state, gen, providerName,
				fmt.Sprintf("late exit-ip lookup saw the pre-VPN baseline %s, traffic is not tunneled", ip))
			return
		}
		if location, ok := state.BackfillExitIP(gen, ip); ok {
			failing.succeeded(location)
			exits.rememberAt(location, ip)
			log.Printf("tundler-tunnel: exit ip %s found %s after the tunnel came up (probe %d)",
				ip, time.Since(start).Round(time.Second), attempt+1)
		}
		return
	}
}

// failDeadTunnel hands tunnel number gen to the watchdog when it is
// still the current, exit-less, Ready tunnel, and counts a failure
// against its location like a connect that came up without a working
// exit.
func failDeadTunnel(state *StateTracker, gen uint64, providerName, why string) {
	location, ok := state.MarkTunnelDead(gen)
	if !ok {
		return
	}
	log.Printf("tundler-tunnel: provider=%s location=%s %s; marking the tunnel failed for the watchdog to replace",
		providerName, location, why)
	noteFailingLocation(providerName, location, "came up without a working exit again", failing.connectFailed(location))
}
