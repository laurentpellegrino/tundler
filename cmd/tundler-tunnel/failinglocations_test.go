package main

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// testClock is a settable clock for the failing-location memory.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newTestClock() *testClock               { return &testClock{t: time.Unix(1_770_000_000, 0)} }
func newTestFailing(c *testClock) *failingLocations {
	f := newFailingLocations(24 * time.Hour)
	f.now = c.now
	return f
}

// withFailing swaps in an enabled failing-location memory on a test clock.
func withFailing(t *testing.T) *testClock {
	t.Helper()
	withHolds(t)
	prev := failing
	t.Cleanup(func() { failing = prev })
	c := newTestClock()
	failing = newTestFailing(c)
	return c
}

func TestCredentialRejectionHoldsTheLocationAtOnceAndDoublesUpToAWeek(t *testing.T) {
	c := newTestClock()
	f := newTestFailing(c)
	want := []time.Duration{24 * time.Hour, 48 * time.Hour, 96 * time.Hour, 168 * time.Hour, 168 * time.Hour}
	for i, w := range want {
		if got := f.authFailed("la-laos"); got != w {
			t.Fatalf("hold %d = %s, want %s", i+1, got, w)
		}
		if !slices.Contains(f.held(), "la-laos") {
			t.Fatalf("hold %d: la-laos must be held", i+1)
		}
		c.advance(w + time.Second)
		if len(f.held()) != 0 {
			t.Fatalf("hold %d: la-laos must come back after %s", i+1, w)
		}
	}
	f.succeeded("la-laos")
	if got := f.authFailed("la-laos"); got != 24*time.Hour {
		t.Fatalf("a success must reset the escalation, got %s", got)
	}
}

func TestFailureDuringAHoldDoesNotExtendIt(t *testing.T) {
	c := newTestClock()
	f := newTestFailing(c)
	f.authFailed("hu")
	c.advance(time.Hour)
	if got := f.authFailed("hu"); got != 0 {
		t.Fatalf("a failure while held (holds ignored for a pick) must not start a new hold, got %s", got)
	}
	c.advance(23*time.Hour + time.Second)
	if len(f.held()) != 0 {
		t.Fatal("the first hold must end on time")
	}
}

func TestConnectFailureHoldsOnlyWhenThePodConnectsElsewhereInBetween(t *testing.T) {
	c := newTestClock()
	f := newTestFailing(c)
	if f.connectFailed("be") != 0 {
		t.Fatal("one failure must not hold a location")
	}
	c.advance(time.Minute)
	if f.connectFailed("be") != 0 {
		t.Fatal("two failures with no success anywhere in between must not hold it")
	}
	c.advance(time.Minute)
	f.succeeded("fr")
	c.advance(time.Minute)
	if got := f.connectFailed("be"); got != 24*time.Hour {
		t.Fatalf("fail, success elsewhere, fail must hold it 24h, got %s", got)
	}
	if !slices.Equal(f.held(), []string{"be"}) {
		t.Fatalf("held = %v, want [be]", f.held())
	}
}

func TestOutageHoldsNothing(t *testing.T) {
	c := newTestClock()
	f := newTestFailing(c)
	f.succeeded("fr")
	c.advance(time.Minute)
	locs := []string{"be", "de", "nl", "pl"}
	for round := 0; round < 3; round++ {
		for _, loc := range locs {
			if got := f.connectFailed(loc); got != 0 {
				t.Fatalf("round %d: %s held for %s during an outage", round, loc, got)
			}
			c.advance(time.Minute)
		}
	}
	if len(f.held()) != 0 {
		t.Fatalf("held = %v, want none", f.held())
	}
}

func TestSuccessForgetsAPendingFailure(t *testing.T) {
	c := newTestClock()
	f := newTestFailing(c)
	f.connectFailed("be")
	c.advance(time.Minute)
	f.succeeded("be")
	c.advance(time.Minute)
	if f.connectFailed("be") != 0 {
		t.Fatal("a success at the location must forget its earlier failure")
	}
}

func TestDisabledMemoryHoldsNothing(t *testing.T) {
	f := newFailingLocations(0)
	f.authFailed("la-laos")
	f.connectFailed("be")
	f.succeeded("fr")
	f.connectFailed("be")
	if len(f.held()) != 0 {
		t.Fatalf("held = %v, want none with the memory disabled", f.held())
	}
	var nilMemory *failingLocations
	if nilMemory.authFailed("x") != 0 || nilMemory.connectFailed("x") != 0 || nilMemory.held() != nil {
		t.Fatal("a nil memory must be a no-op")
	}
	nilMemory.succeeded("x")
}

func TestPickSkipsHeldLocationsAndIgnoresHoldsWhenNothingIsLeft(t *testing.T) {
	withFailing(t)
	failing.authFailed("a")
	for i := 0; i < 50; i++ {
		loc, _, err := pickPreferredLocation(nil, []string{"a", "b"}, nil)
		if err != nil || loc != "b" {
			t.Fatalf("pick = %q, %v; want b", loc, err)
		}
	}
	loc, _, err := pickPreferredLocation(nil, []string{"a", "b"}, []string{"b"})
	if err != nil || loc != "a" {
		t.Fatalf("with b excluded and a held, pick = %q, %v; want a (holds ignored)", loc, err)
	}
	if _, _, err := pickPreferredLocation(nil, []string{"a"}, []string{"a"}); !errors.Is(err, errNoAllowedLocations) {
		t.Fatalf("static exclusions still apply, got %v", err)
	}
}

func TestRotationCredentialRejectionHoldsThatLocation(t *testing.T) {
	withFailing(t)
	fp := &fakeProvider{locations: []string{"la-laos", "hu"}, authFail: true}
	err := connectWithRetry(context.Background(), fp, NewStateTracker("fake"), "fake", []string{"hu"}, 3, (&noSleep{}).sleep, "")
	if !errors.Is(err, errAuthFailed) {
		t.Fatalf("rotation must fail with errAuthFailed, got %v", err)
	}
	if !slices.Equal(failing.held(), []string{"la-laos"}) {
		t.Fatalf("held = %v, want [la-laos]", failing.held())
	}
}

func TestRotationHoldsALocationThatFailsAgainAfterASuccess(t *testing.T) {
	c := withFailing(t)
	fp := &fakeProvider{locations: []string{"be", "fr"}, connectOK: true, connectIP: "198.51.100.7",
		failLocations: map[string]bool{"be": true}}
	st := NewStateTracker("fake")
	// be fails, the rotation moves on to fr and succeeds.
	if err := connectWithRetry(context.Background(), fp, st, "fake", []string{"fr"}, 1, (&noSleep{}).sleep, ""); err == nil {
		t.Fatal("be is the only allowed location and must fail")
	}
	c.advance(time.Minute)
	if err := connectWithRetry(context.Background(), fp, st, "fake", []string{"be"}, 1, (&noSleep{}).sleep, ""); err != nil {
		t.Fatalf("fr must connect: %v", err)
	}
	c.advance(time.Minute)
	if len(failing.held()) != 0 {
		t.Fatalf("one failure must hold nothing, held = %v", failing.held())
	}
	_ = connectWithRetry(context.Background(), fp, st, "fake", []string{"fr"}, 1, (&noSleep{}).sleep, "")
	if !slices.Equal(failing.held(), []string{"be"}) {
		t.Fatalf("held = %v, want [be]", failing.held())
	}
}

func TestReconnectAvoidsALocationThatFailedSinceTheLastSuccess(t *testing.T) {
	c := withFailing(t)
	fp := &fakeProvider{locations: []string{"ec", "pl"}, connectOK: true, connectIP: "198.51.100.7",
		failLocations: map[string]bool{"ec": true}}
	st := NewStateTracker("fake")
	if _, err := connectTunnelAt(context.Background(), fp, st, "fake", []string{"pl"}, ""); err == nil {
		t.Fatal("ec must fail")
	}
	if len(failing.held()) != 0 {
		t.Fatalf("one failure holds nothing, held = %v", failing.held())
	}
	c.advance(time.Minute)
	// The watchdog reconnects with only the static exclusions: it must
	// not go back to ec.
	for i := 0; i < 50; i++ {
		if loc, _, err := pickPreferredLocation(nil, fp.locations, nil); err != nil || loc != "pl" {
			t.Fatalf("pick = %q, %v; want pl", loc, err)
		}
	}
	if loc, err := connectTunnelAt(context.Background(), fp, st, "fake", nil, ""); err != nil || loc != "pl" {
		t.Fatalf("reconnect = %q, %v; want pl", loc, err)
	}
	// Once the pod connected elsewhere ec is offered again (and held if
	// it fails once more).
	seen := false
	for i := 0; i < 100 && !seen; i++ {
		loc, _, _ := pickPreferredLocation(nil, fp.locations, nil)
		seen = loc == "ec"
	}
	if !seen {
		t.Fatal("ec must be offered again after a success elsewhere")
	}
}

func TestEveryLocationFailedSinceTheLastSuccessIsTriedAgain(t *testing.T) {
	withFailing(t)
	failing.connectFailed("ec")
	failing.connectFailed("pl")
	got := slices.Clone(failing.unsettled())
	slices.Sort(got)
	if !slices.Equal(got, []string{"ec", "pl"}) {
		t.Fatalf("unsettled = %v", got)
	}
	if loc, _, err := pickPreferredLocation(nil, []string{"ec", "pl"}, nil); err != nil || loc == "" {
		t.Fatalf("an outage must not leave the pod without a pick: %q, %v", loc, err)
	}
}
