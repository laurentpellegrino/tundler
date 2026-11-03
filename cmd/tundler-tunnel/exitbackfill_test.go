package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// withBackfillProbe swaps the egress probe for one test.
func withBackfillProbe(t *testing.T, probe func(context.Context) (string, error)) {
	t.Helper()
	withHolds(t)
	prev := probeExitForBackfill
	t.Cleanup(func() { probeExitForBackfill = prev })
	probeExitForBackfill = probe
}

// noWait is a wait func that never sleeps and counts its calls.
type noWait struct{ calls atomic.Int32 }

func (w *noWait) wait(ctx context.Context, _ time.Duration) bool {
	w.calls.Add(1)
	return ctx.Err() == nil
}

func TestBackfillRecordsTheExitOnceTheProbeAnswers(t *testing.T) {
	var probes atomic.Int32
	withBackfillProbe(t, func(context.Context) (string, error) {
		if probes.Add(1) < 3 {
			return "", errors.New("context deadline exceeded")
		}
		return "198.51.100.9", nil
	})
	st := NewStateTracker("fake")
	var heard string
	st.SetTunnelUpListener(func(ip string) { heard = ip })
	st.RecordTunnelUp("br", "")
	backfillExitIP(context.Background(), st, st.TunnelUpCount(), "203.0.113.1", (&noWait{}).wait)
	if got := st.SnapshotCurrentExitIP(); got != "198.51.100.9" {
		t.Fatalf("exit = %q, want 198.51.100.9", got)
	}
	if heard != "198.51.100.9" {
		t.Fatalf("listener heard %q, want the late exit (proxy header and tunnel_up event)", heard)
	}
	if probes.Load() != 3 {
		t.Fatalf("probes = %d, want 3 (two failures, then the answer)", probes.Load())
	}
}

func TestBackfillStopsWhenTheTunnelIsReplaced(t *testing.T) {
	st := NewStateTracker("fake")
	st.RecordTunnelUp("br", "")
	gen := st.TunnelUpCount()
	withBackfillProbe(t, func(context.Context) (string, error) {
		// A rotation lands while the probe runs.
		st.RecordTunnelUp("de", "192.0.2.4")
		return "198.51.100.9", nil
	})
	backfillExitIP(context.Background(), st, gen, "", (&noWait{}).wait)
	if got := st.SnapshotCurrentExitIP(); got != "192.0.2.4" {
		t.Fatalf("exit = %q; a late answer must not overwrite the next tunnel's exit", got)
	}
}

func TestBackfillDoesNothingWhenTheExitIsAlreadyKnown(t *testing.T) {
	withBackfillProbe(t, func(context.Context) (string, error) {
		t.Fatal("no probe when the exit is known")
		return "", nil
	})
	st := NewStateTracker("fake")
	st.RecordTunnelUp("de", "192.0.2.4")
	backfillExitIP(context.Background(), st, st.TunnelUpCount(), "", (&noWait{}).wait)
}

func TestBackfillTreatsTheBaselineAsALeakNotAnExit(t *testing.T) {
	withBackfillProbe(t, func(context.Context) (string, error) { return "203.0.113.1", nil })
	st := NewStateTracker("fake")
	st.RecordTunnelUp("br", "")
	backfillExitIP(context.Background(), st, st.TunnelUpCount(), "203.0.113.1", (&noWait{}).wait)
	if got := st.SnapshotCurrentExitIP(); got != "" {
		t.Fatalf("exit = %q; the pre-VPN address must never be recorded as the exit", got)
	}
}

func TestBackfillStopsWithTheProcess(t *testing.T) {
	withBackfillProbe(t, func(context.Context) (string, error) { return "", errors.New("timeout") })
	st := NewStateTracker("fake")
	st.RecordTunnelUp("br", "")
	ctx, cancel := context.WithCancel(context.Background())
	w := &noWait{}
	done := make(chan struct{})
	go func() {
		backfillExitIP(ctx, st, st.TunnelUpCount(), "", func(c context.Context, d time.Duration) bool {
			if w.calls.Load() == 5 {
				cancel()
			}
			return w.wait(c, d)
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup must stop when the process context ends")
	}
}

func TestBackfillDelaysEndAtTwoMinutes(t *testing.T) {
	var got []time.Duration
	withBackfillProbe(t, func(context.Context) (string, error) { return "", errors.New("timeout") })
	st := NewStateTracker("fake")
	st.RecordTunnelUp("br", "")
	backfillExitIP(context.Background(), st, st.TunnelUpCount(), "", func(_ context.Context, d time.Duration) bool {
		got = append(got, d)
		return len(got) < 6
	})
	want := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 2 * time.Minute, 2 * time.Minute}
	if len(got) != len(want) {
		t.Fatalf("delays = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delays = %v, want %v", got, want)
		}
	}
}

func TestBackfillExitIPRejectsAStaleGeneration(t *testing.T) {
	st := NewStateTracker("fake")
	st.RecordTunnelUp("br", "")
	old := st.TunnelUpCount()
	st.RecordTunnelUp("de", "")
	if st.BackfillExitIP(old, "198.51.100.9") {
		t.Fatal("an exit found for a previous tunnel must be dropped")
	}
	if !st.BackfillExitIP(st.TunnelUpCount(), "198.51.100.9") || st.SnapshotCurrentExitIP() != "198.51.100.9" {
		t.Fatal("the current tunnel's exit must be recorded")
	}
	if st.BackfillExitIP(st.TunnelUpCount(), "198.51.100.10") {
		t.Fatal("a known exit must not be overwritten")
	}
}
