package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestThrottleHoldDoublesAndCapsAtThirtyMinutes(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	h := newThrottleHold(5 * time.Minute)
	h.now = func() time.Time { return now }
	want := []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i, w := range want {
		if got := h.strike(); got != w {
			t.Fatalf("strike %d = %s, want %s", i+1, got, w)
		}
	}
	h.clear()
	if h.remaining() != 0 || h.strike() != 5*time.Minute {
		t.Fatal("clear must drop the hold and reset the strike count")
	}
}

// withHolds swaps in fresh holds and test-friendly globals for one test.
func withHolds(t *testing.T) {
	t.Helper()
	prevH, prevT, prevB, prevE, prevP := hold, throttle, blocked, exits, pref
	t.Cleanup(func() { hold, throttle, blocked, exits, pref = prevH, prevT, prevB, prevE, prevP })
	hold = newAuthHold(time.Hour)
	throttle = newThrottleHold(5 * time.Minute)
	blocked, _ = newTestCooldown(time.Hour)
	exits = newExitMemory(time.Hour)
	pref = nil
}

func TestRotationStopsAtThrottleAndHolds(t *testing.T) {
	withHolds(t)
	fp := &fakeProvider{locations: []string{"Portugal", "Spain", "France"}, throttled: true}
	st := NewStateTracker("fake")
	ns := &noSleep{}
	err := connectWithRetry(context.Background(), fp, st, "fake", nil, 3, ns.sleep, "")
	if !errors.Is(err, errThrottled) {
		t.Fatalf("rotation must fail with errThrottled, got %v", err)
	}
	// One attempt, not three: another location is refused the same way.
	if len(fp.calls) != 1 {
		t.Fatalf("connect calls = %v, want exactly one", fp.calls)
	}
	if throttle.remaining() <= 0 {
		t.Fatal("a throttle refusal must start the throttle hold")
	}
	if hold.remaining() != 0 {
		t.Fatal("a throttle refusal is not an auth failure")
	}
	if snap := st.Snapshot(); snap.AuthFailuresTotal != 0 || snap.AuthHoldUntil != "" {
		t.Fatalf("a throttle refusal must not count as an auth failure: %+v", snap)
	}

	// Boot path: the throttle hold replaces the short backoff.
	var waited []time.Duration
	backoff := func(int) time.Duration { return time.Second }
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_ = connectInitialWithRetryObserved(ctx, fp, st, "fake", nil, "", backoff, func(d time.Duration) { waited = append(waited, d) })
	if len(waited) == 0 || waited[0] < 4*time.Minute {
		t.Fatalf("boot retry must wait out the throttle hold, waited %v", waited)
	}

	// The refusal lifts: the next successful connect clears the hold.
	fp.mu.Lock()
	fp.throttled, fp.connectOK, fp.connectIP = false, true, "5.5.5.5"
	fp.mu.Unlock()
	throttle.until = time.Time{}
	if err := connectWithRetry(context.Background(), fp, st, "fake", nil, 3, ns.sleep, ""); err != nil {
		t.Fatalf("connect after the hold: %v", err)
	}
	if throttle.remaining() != 0 || throttle.strikesCount() != 0 {
		t.Fatal("a successful connect must clear the throttle hold")
	}
}

func TestRotatorKeepsTheTunnelDuringThrottleHold(t *testing.T) {
	withHolds(t)
	throttle.strike()
	fp := &fakeProvider{locations: []string{"Portugal"}, connectOK: true}
	st := NewStateTracker("fake")
	st.RecordTunnelUp("Portugal", "1.2.3.4")
	st.Set(StateReady)
	rotateIfReady(context.Background(), fp, st, "fake", nil, nil, "")
	if fp.callCount() != 0 || fp.disconnectCalls.Load() != 0 {
		t.Fatalf("rotator must not disconnect or connect during the hold (connects %d, disconnects %d)",
			fp.callCount(), fp.disconnectCalls.Load())
	}
	if st.Get() != StateReady {
		t.Fatalf("state = %s, want Ready", st.Get())
	}
}

func TestRotateHandlerHoldsDuringThrottleHold(t *testing.T) {
	withHolds(t)
	throttle.strike()
	st := NewStateTracker("fake")
	st.RecordTunnelUp("Portugal", "1.2.3.4")
	st.Set(StateReady)
	triggered := false
	h := rotateHandler(st, func() { triggered = true })
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/rotate", nil))
	if rr.Code != http.StatusOK || triggered {
		t.Fatalf("got %d triggered=%v, want 200 and no rotation", rr.Code, triggered)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(body["message"], "connect-throttle hold") {
		t.Errorf("message=%q, want the throttle hold", body["message"])
	}
}
