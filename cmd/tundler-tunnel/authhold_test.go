package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAuthHoldDoublesAndCaps(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	h := newAuthHold(time.Hour)
	h.now = func() time.Time { return now }
	if h.remaining() != 0 {
		t.Fatal("fresh hold must be free")
	}
	want := []time.Duration{time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 16 * time.Hour, 24 * time.Hour, 24 * time.Hour}
	for i, w := range want {
		if got := h.strike(); got != w {
			t.Fatalf("strike %d = %s, want %s", i+1, got, w)
		}
	}
	if h.remaining() != 24*time.Hour {
		t.Fatalf("remaining = %s, want the full cap", h.remaining())
	}
	now = now.Add(23 * time.Hour)
	if h.remaining() != time.Hour {
		t.Fatalf("remaining after 23h = %s, want 1h", h.remaining())
	}
	now = now.Add(2 * time.Hour)
	if h.remaining() != 0 {
		t.Fatal("an elapsed hold must be free")
	}
	h.clear()
	if h.strike() != time.Hour {
		t.Fatal("clear must reset the strike count")
	}
	h.clear()
	if h.remaining() != 0 || !h.deadline().IsZero() {
		t.Fatal("clear must drop the deadline")
	}
}

func TestRotationStopsAtAuthFailureAndHolds(t *testing.T) {
	prevH, prevB, prevE, prevP := hold, blocked, exits, pref
	t.Cleanup(func() { hold, blocked, exits, pref = prevH, prevB, prevE, prevP })
	hold = newAuthHold(time.Hour)
	blocked, _ = newTestCooldown(time.Hour)
	exits = newExitMemory(time.Hour)
	pref = nil

	fp := &fakeProvider{locations: []string{"USA", "Canada", "Germany"}, authFail: true}
	st := NewStateTracker("fake")
	ns := &noSleep{}
	err := connectWithRetry(context.Background(), fp, st, "fake", nil, 3, ns.sleep, "")
	if !errors.Is(err, errAuthFailed) {
		t.Fatalf("rotation must fail with errAuthFailed, got %v", err)
	}
	// One login, not three: other locations cannot help.
	if len(fp.calls) != 1 {
		t.Fatalf("connect calls = %v, want exactly one", fp.calls)
	}
	if hold.remaining() <= 0 {
		t.Fatal("an auth failure must start the hold")
	}
	snap := st.Snapshot()
	if snap.AuthFailuresTotal != 1 || snap.AuthHoldUntil == "" {
		t.Fatalf("status must show the failure and the hold: %+v", snap)
	}

	// Boot path: the hold replaces the short backoff.
	var waited []time.Duration
	backoff := func(int) time.Duration { return time.Second }
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Let one attempt run, then stop the loop.
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_ = connectInitialWithRetryObserved(ctx, fp, st, "fake", nil, "", backoff, func(d time.Duration) { waited = append(waited, d) })
	if len(waited) == 0 || waited[0] < 50*time.Minute {
		t.Fatalf("boot retry must wait out the hold, waited %v", waited)
	}

	// Credentials fixed: the next successful connect clears everything.
	fp.mu.Lock()
	fp.authFail, fp.connectOK, fp.connectIP = false, true, "5.5.5.5"
	fp.mu.Unlock()
	hold.until = time.Time{} // the operator waited it out
	if err := connectWithRetry(context.Background(), fp, st, "fake", nil, 3, ns.sleep, ""); err != nil {
		t.Fatalf("connect after the hold: %v", err)
	}
	if hold.remaining() != 0 || hold.strikesCount() != 0 || st.Snapshot().AuthHoldUntil != "" {
		t.Fatal("a successful connect must clear the hold")
	}
}
