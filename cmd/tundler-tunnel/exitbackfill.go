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
// it gets one, the tunnel is replaced, or the process stops. A probe
// that returns the pre-VPN baseline is a leak, not an exit: it is
// logged and the lookup stops, leaving the exit empty.

import (
	"context"
	"log"
	"time"
)

var exitBackfillDelays = []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute}

// probeExitForBackfill is the egress probe; tests replace it.
var probeExitForBackfill = probeContractEgressIP

// startExitIPBackfill looks the current tunnel's exit IP up in the
// background. Call it right after RecordTunnelUp with an empty exit.
func startExitIPBackfill(ctx context.Context, state *StateTracker, baseline string) {
	gen := state.TunnelUpCount()
	go backfillExitIP(ctx, state, gen, baseline, sleepCtx)
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

func backfillExitIP(ctx context.Context, state *StateTracker, gen uint64, baseline string, wait func(context.Context, time.Duration) bool) {
	start := time.Now()
	for attempt := 0; ; attempt++ {
		d := exitBackfillDelays[min(attempt, len(exitBackfillDelays)-1)]
		if !wait(ctx, d) {
			return
		}
		if state.TunnelUpCount() != gen || state.SnapshotCurrentExitIP() != "" {
			return // replaced, or the exit became known another way
		}
		ip, err := probeExitForBackfill(ctx)
		if err != nil || ip == "" {
			continue
		}
		if state.TunnelUpCount() != gen {
			return // a rotation started while the probe ran
		}
		if baseline != "" && ip == baseline {
			log.Printf("tundler-tunnel: late exit-ip lookup saw the pre-VPN baseline %s — traffic is not tunneled; leaving the exit unknown", ip)
			return
		}
		if state.BackfillExitIP(gen, ip) {
			exits.remember(ip)
			log.Printf("tundler-tunnel: exit ip %s found %s after the tunnel came up (probe %d)",
				ip, time.Since(start).Round(time.Second), attempt+1)
		}
		return
	}
}
