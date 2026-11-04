package main

import (
	"context"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	_ "github.com/laurentpellegrino/tundler/internal/provider/fastvpn"
	"github.com/laurentpellegrino/tundler/internal/proxy"
)

func TestWedgeClockTripsAfterTheThreshold(t *testing.T) {
	c := wedgeClock{threshold: 15 * time.Minute}
	t0 := time.Now()
	if _, _, trip := c.observe(StateFailed, t0); trip {
		t.Fatal("tripped on the first non-Ready sample")
	}
	if _, _, trip := c.observe(StateFailed, t0.Add(10*time.Minute)); trip {
		t.Fatal("tripped before the threshold")
	}
	if _, elapsed, trip := c.observe(StateConnecting, t0.Add(16*time.Minute)); !trip || elapsed != 16*time.Minute {
		t.Fatalf("did not trip past the threshold (elapsed=%s)", elapsed)
	}
	if cleared, _, _ := c.observe(StateReady, t0.Add(17*time.Minute)); cleared != 17*time.Minute {
		t.Fatalf("cleared after %s, want 17m", cleared)
	}
}

func TestWedgeClockLeavesADaemonlessProviderRetrying(t *testing.T) {
	c := wedgeClock{threshold: 15 * time.Minute, daemonless: true}
	t0 := time.Now()
	// An hour of failed reconnects, each attempt Connecting for 30 s
	// between Failed samples: the watchdog is pacing, not wedged.
	for m := 0; m < 60; m++ {
		at := t0.Add(time.Duration(m) * time.Minute)
		if _, _, trip := c.observe(StateFailed, at); trip {
			t.Fatalf("tripped on Failed at minute %d", m)
		}
		if _, _, trip := c.observe(StateConnecting, at.Add(30*time.Second)); trip {
			t.Fatalf("tripped on a short attempt at minute %d", m)
		}
	}
	// A connect that hangs for the whole threshold still trips.
	t1 := t0.Add(2 * time.Hour)
	c.observe(StateConnecting, t1)
	if _, _, trip := c.observe(StateConnecting, t1.Add(16*time.Minute)); !trip {
		t.Fatal("a hung connect did not trip")
	}
}

func TestRunnerProvidersAreDaemonless(t *testing.T) {
	if _, ok := provider.Registry["fastvpn"].(provider.Daemonless); !ok {
		t.Fatal("fastvpn runs an owned openvpn child and must be Daemonless")
	}
}

// countReconnects runs the watchdog against a provider that never
// connects and returns how many reconnects it made in window.
func countReconnects(t *testing.T, daemonless bool, window time.Duration) int {
	t.Helper()
	fp := &fakeProvider{locations: []string{"USA"}, connectOK: false}
	st := NewStateTracker("fake")
	st.Set(StateFailed)
	ctx, cancel := context.WithTimeout(context.Background(), window)
	defer cancel()
	runWatchdog(ctx, fp, st, "fake", nil, time.Millisecond, proxy.New("", "", ""), "", daemonless)
	return fp.callCount()
}

func TestWatchdogBacksOffFurtherForADaemonlessProvider(t *testing.T) {
	defer withWatchdogBackoff(2*time.Millisecond, 4*time.Millisecond)()
	prev := watchdogDaemonlessMaxBackoff
	watchdogDaemonlessMaxBackoff = time.Hour
	defer func() { watchdogDaemonlessMaxBackoff = prev }()
	daemon := countReconnects(t, false, 300*time.Millisecond)
	owned := countReconnects(t, true, 300*time.Millisecond)
	// Daemon-backed: a retry every few ms (capped at 4 ms). Daemonless:
	// 2, 4, 8, … 256 ms, so at most 8 attempts in 300 ms.
	t.Logf("reconnects in 300 ms: daemon-backed=%d daemonless=%d", daemon, owned)
	if owned < 3 || owned > 8 || daemon < 2*owned {
		t.Fatalf("daemonless reconnects=%d, daemon-backed=%d: want the daemonless backoff to keep doubling", owned, daemon)
	}
}
