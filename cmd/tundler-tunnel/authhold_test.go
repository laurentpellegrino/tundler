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

	fp := &fakeProvider{locations: []string{"USA", "Canada", "Germany", "France"}, authFail: true}
	st := NewStateTracker("fake")
	ns := &noSleep{}
	err := connectWithRetry(context.Background(), fp, st, "fake", nil, 4, ns.sleep, "")
	if !errors.Is(err, errAuthFailed) {
		t.Fatalf("rotation must fail with errAuthFailed, got %v", err)
	}
	// Three rejections in a row (each at a different location) start
	// the hold; there is no fourth login.
	if len(fp.calls) != 3 {
		t.Fatalf("connect calls = %v, want exactly three", fp.calls)
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

func TestOneLocationRejectingTheCredentialsMovesOnWithoutTheAccountHold(t *testing.T) {
	withFailing(t)
	fp := &fakeProvider{locations: []string{"lv", "de"}, connectOK: true, connectIP: "198.51.100.7",
		authFailLocations: map[string]bool{"lv": true}}
	for i := 0; i < 20; i++ {
		failing = newFailingLocations(0) // no memory: the rotation's own retry list must do it
		hold = newAuthHold(time.Hour)
		exits = newExitMemory(time.Hour) // the same exit IP every round is not a burnt prefix here
		fp.calls = nil
		st := NewStateTracker("fake")
		if err := connectWithRetry(context.Background(), fp, st, "fake", nil, 2, (&noSleep{}).sleep, ""); err != nil {
			t.Fatalf("the rotation must land on de: %v (calls %v)", err, fp.calls)
		}
		if last := fp.calls[len(fp.calls)-1]; last != "de" {
			t.Fatalf("calls = %v, want to end on de", fp.calls)
		}
		if hold.remaining() != 0 || st.Snapshot().AuthFailuresTotal != 0 {
			t.Fatalf("one refusing location must not hold or count against the account: %+v", st.Snapshot())
		}
	}
}

func TestReconnectSkipsTheLocationThatRejectedTheCredentials(t *testing.T) {
	withFailing(t)
	fp := &fakeProvider{locations: []string{"lv", "de"}, connectOK: true, connectIP: "198.51.100.7",
		authFailLocations: map[string]bool{"lv": true}}
	st := NewStateTracker("fake")
	_, err := connectTunnelAt(context.Background(), fp, st, "fake", []string{"de"}, "")
	if err == nil || errors.Is(err, errAuthFailed) {
		t.Fatalf("one refusing location is not an account failure, got %v", err)
	}
	if hold.remaining() != 0 {
		t.Fatalf("auth hold = %s, want none", hold.remaining())
	}
	if held := failing.held(); len(held) != 1 || held[0] != "lv" {
		t.Fatalf("held = %v, want [lv]", held)
	}
	if loc, err := connectTunnelAt(context.Background(), fp, st, "fake", nil, ""); err != nil || loc != "de" {
		t.Fatalf("reconnect = %q, %v; want de", loc, err)
	}
}

func TestASuccessResetsTheRejectionCount(t *testing.T) {
	withFailing(t)
	fp := &fakeProvider{locations: []string{"a", "b", "c", "d"}, connectOK: true, connectIP: "198.51.100.7",
		authFailLocations: map[string]bool{"a": true, "b": true, "d": true}}
	st := NewStateTracker("fake")
	for _, only := range []string{"a", "b", "c", "d"} {
		var others []string
		for _, l := range fp.locations {
			if l != only {
				others = append(others, l)
			}
		}
		_, _ = connectTunnelAt(context.Background(), fp, st, "fake", others, "")
	}
	if r := hold.remaining(); r != 0 {
		t.Fatalf("a, b, success on c, then d: no auth hold expected, got %s", r)
	}
}

func TestAfterTheHoldOneMoreRejectionHoldsAgainAtTheDoubledLength(t *testing.T) {
	withFailing(t)
	fp := &fakeProvider{locations: []string{"a", "b", "c", "d"}, authFail: true}
	st := NewStateTracker("fake")
	if err := connectWithRetry(context.Background(), fp, st, "fake", nil, 5, (&noSleep{}).sleep, ""); !errors.Is(err, errAuthFailed) {
		t.Fatalf("want errAuthFailed after three rejections, got %v", err)
	}
	hold.until = time.Time{} // the first hold ran out
	fp.calls = nil
	if err := connectWithRetry(context.Background(), fp, st, "fake", nil, 5, (&noSleep{}).sleep, ""); !errors.Is(err, errAuthFailed) {
		t.Fatalf("want errAuthFailed at once, got %v", err)
	}
	if len(fp.calls) != 1 {
		t.Fatalf("calls = %v, want one login after the hold", fp.calls)
	}
	if r := hold.remaining(); r < 119*time.Minute {
		t.Fatalf("second hold = %s, want 2h", r)
	}
}

func TestAuthFailuresBeforeHoldFromEnv(t *testing.T) {
	t.Setenv(envAuthFailuresBeforeHold, "1")
	h := newAuthHoldFromEnv()
	if starts, _ := h.reject(); !starts {
		t.Fatal("a threshold of 1 must hold on the first rejection")
	}
	t.Setenv(envAuthFailuresBeforeHold, "")
	if h := newAuthHoldFromEnv(); h.threshold != defaultAuthFailuresBefore {
		t.Fatalf("threshold = %d, want the default %d", h.threshold, defaultAuthFailuresBefore)
	}
}
