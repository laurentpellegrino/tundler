package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestCooldown(ttl time.Duration) (*locationCooldown, *time.Time) {
	now := time.Unix(1_770_000_000, 0)
	c := newLocationCooldown(ttl)
	c.now = func() time.Time { return now }
	return c, &now
}

func TestCooldownMarkExpires(t *testing.T) {
	c, now := newTestCooldown(time.Hour)
	c.mark("Belgium", "BE")
	if !c.cooledLocation("Belgium") || !c.cooledCountry("BE") {
		t.Fatal("marked entries must be cooling")
	}
	if locs, ccs := c.counts(); locs != 1 || ccs != 1 {
		t.Fatalf("counts = %d/%d, want 1/1", locs, ccs)
	}
	*now = now.Add(time.Hour)
	if c.cooledLocation("Belgium") || c.cooledCountry("BE") || len(c.cooledLocations()) != 0 {
		t.Fatal("entries must expire after ttl")
	}
}

func TestCooldownDisabledAndNil(t *testing.T) {
	c, _ := newTestCooldown(0)
	c.mark("Belgium", "BE")
	if c.cooledLocation("Belgium") {
		t.Fatal("ttl 0 must make mark a no-op")
	}
	var none *locationCooldown
	none.mark("x", "XX")
	if none.cooledLocation("x") || none.cooledCountry("XX") || none.cooledLocations() != nil {
		t.Fatal("nil cooldown must answer 'not cooling'")
	}
}

func TestCooldownFromEnv(t *testing.T) {
	t.Setenv(envBlockedCooldown, "")
	if c := newLocationCooldownFromEnv(); c.ttl != defaultBlockedCooldown {
		t.Fatalf("default ttl = %s", c.ttl)
	}
	t.Setenv(envBlockedCooldown, "90m")
	if c := newLocationCooldownFromEnv(); c.ttl != 90*time.Minute {
		t.Fatalf("ttl = %s, want 90m", c.ttl)
	}
	t.Setenv(envBlockedCooldown, "soon")
	if c := newLocationCooldownFromEnv(); c.ttl != defaultBlockedCooldown {
		t.Fatalf("invalid value must keep the default, got %s", c.ttl)
	}
}

func TestRotateHandlerReasonIsLoggedNotActedOn(t *testing.T) {
	prev := blocked
	t.Cleanup(func() { blocked = prev })
	blocked, _ = newTestCooldown(time.Hour)

	st := NewStateTracker("fake")
	st.RecordTunnelUp("Belgium", "1.2.3.4")
	st.RecordCountry("BE", "BE")
	st.Set(StateReady)
	triggered := make(chan struct{}, 1)
	h := rotateHandler(st, func() { triggered <- struct{}{} })

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rotate", strings.NewReader(`{"reason":"blocked"}`))
	req.Header.Set("Content-Type", "application/json")
	h(rr, req)
	<-triggered
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	// A throttled IP says nothing about the pool: the handler must not
	// cool anything, the verdict comes from the exit the rotation lands on.
	if blocked.cooledLocation("Belgium") || blocked.cooledCountry("BE") {
		t.Fatal("reason=blocked must not cool the location or country")
	}
	if got := rotateReason(httptest.NewRequest(http.MethodPost, "/rotate?reason=Blocked", nil)); got != "blocked" {
		t.Fatalf("query reason = %q", got)
	}
}

func TestExitMemoryRepeatAndExpiry(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	m := newExitMemory(time.Hour)
	m.now = func() time.Time { return now }
	if m.remember("1.1.1.1") {
		t.Fatal("first sight is not a repeat")
	}
	if !m.remember("1.1.1.1") {
		t.Fatal("second sight within ttl is a repeat")
	}
	if !m.remember("1.1.1.200") {
		t.Fatal("another address in the same /24 is a repeat")
	}
	if m.remember("1.1.2.1") {
		t.Fatal("a different /24 is not a repeat")
	}
	if m.remember("") {
		t.Fatal("empty exit is never a repeat")
	}
	if m.remember("2001:db8:1::1") || !m.remember("2001:db8:1:ffff::9") || m.remember("2001:db8:2::1") {
		t.Fatal("IPv6 exits are remembered by /48")
	}
	if m.remember("not-an-ip") || !m.remember("not-an-ip") {
		t.Fatal("unparseable exits fall back to exact-match memory")
	}
	now = now.Add(time.Hour)
	if m.remember("1.1.1.1") {
		t.Fatal("sight after ttl is not a repeat")
	}
	if m.size() != 1 {
		t.Fatalf("size = %d, want 1", m.size())
	}
	if exitKey("1.2.3.4") != "1.2.3.0/24" || exitKey("::ffff:1.2.3.4") != "1.2.3.0/24" || exitKey("2001:db8:1:2::3") != "2001:db8:1::/48" {
		t.Fatalf("exitKey: %s %s %s", exitKey("1.2.3.4"), exitKey("::ffff:1.2.3.4"), exitKey("2001:db8:1:2::3"))
	}
	var none *exitMemory
	if none.remember("1.1.1.1") || newExitMemory(0).remember("x") || newExitMemory(0).remember("x") {
		t.Fatal("nil or disabled memory never reports a repeat")
	}
}

func TestDwellAdvancesOnlyAtCap(t *testing.T) {
	p := newStridedPref(1, 4)
	p.dwellCap = 3
	_, start, _ := p.pick(bigCatalog, nil)
	if p.rotated("x") || p.rotated("x") {
		t.Fatal("walk must not move before the cap")
	}
	if _, cc, _ := p.pick(bigCatalog, nil); cc != start {
		t.Fatalf("re-pick before the cap left %s for %s", start, cc)
	}
	if !p.rotated("x") {
		t.Fatal("third rotation reaches the cap")
	}
	if _, cc, _ := p.pick(bigCatalog, nil); cc == start {
		t.Fatal("walk must move at the cap")
	}
	// leave() moves on regardless of the dwell count.
	_, here, _ := p.pick(bigCatalog, nil)
	p.rotated("x")
	p.leave()
	if _, cc, _ := p.pick(bigCatalog, nil); cc == here {
		t.Fatal("leave() must move the walk")
	}
	// dwellCap 0 keeps the pre-dwell behaviour: every rotation advances.
	q := newStridedPref(1, 4)
	if !q.rotated("x") {
		t.Fatal("dwellCap 0 advances on every rotation")
	}
}

func TestRotationAvoidsTheLocationItLeaves(t *testing.T) {
	p := newStridedPref(0, 1)
	p.dwellCap = 10
	catalog := []string{"de-berlin", "de-frankfurt"}
	loc, _, _ := p.pick(catalog, nil)
	p.rotated(loc)
	for i := 0; i < 20; i++ {
		if again, _, _ := p.pick(catalog, nil); again == loc {
			t.Fatalf("re-pick returned the location just left (%s)", loc)
		}
	}
	p.settled()
	// A single-location country keeps its only location.
	q := newStridedPref(0, 1)
	q.dwellCap = 10
	q.rotated("belgium")
	if again, _, ok := q.pick([]string{"belgium"}, nil); !ok || again != "belgium" {
		t.Fatalf("single location must still be picked, got %q", again)
	}
}

func TestRepeatExitCoolsCountryAndMovesTheWalk(t *testing.T) {
	prevB, prevE, prevP := blocked, exits, pref
	t.Cleanup(func() { blocked, exits, pref = prevB, prevE, prevP })
	blocked, _ = newTestCooldown(time.Hour)
	exits = newExitMemory(time.Hour)
	pref = newStridedPref(0, 1)
	pref.dwellCap = 10

	noteRotationExit("belgium", "BE", "5.5.5.5")
	if blocked.cooledCountry("BE") || pref.steps.Load() != 0 {
		t.Fatal("a fresh exit must not cool or move anything")
	}
	noteRotationExit("belgium", "BE", "5.5.5.5")
	if !blocked.cooledLocation("belgium") || !blocked.cooledCountry("BE") {
		t.Fatal("a repeated exit must cool the location and country")
	}
	if pref.steps.Load() != 1 {
		t.Fatalf("a repeated exit must move the walk, steps = %d", pref.steps.Load())
	}
	// Country derived from the location when the pick was the random fallback.
	noteRotationExit("Germany", "", "6.6.6.6")
	noteRotationExit("Germany", "", "6.6.6.6")
	if !blocked.cooledCountry("DE") {
		t.Fatal("country must be derived from the location on the fallback path")
	}
}

func TestConnectWithRetryRepeatExitIsDetected(t *testing.T) {
	prevB, prevE, prevP := blocked, exits, pref
	t.Cleanup(func() { blocked, exits, pref = prevB, prevE, prevP })
	blocked, _ = newTestCooldown(time.Hour)
	exits = newExitMemory(time.Hour)
	pref = nil

	// Second rotation lands in the /24 of the first; the retry must go
	// somewhere else (Canada, the only other location) and succeed.
	sp := newScriptedProvider([]string{"USA", "Canada"}, []bool{true, true, true}, []string{"2.2.2.2", "2.2.2.9", "3.3.3.3"})
	st := NewStateTracker("scripted")
	ns := &noSleep{}
	if err := connectWithRetry(context.Background(), sp, st, "scripted", []string{"Canada"}, 3, ns.sleep, ""); err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	if blocked.cooledLocation("USA") {
		t.Fatal("first exit is fresh")
	}
	if err := connectWithRetry(context.Background(), sp, st, "scripted", nil, 3, ns.sleep, ""); err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	// The pick is random between the two locations: whichever got the
	// burnt exit must be cooled, the other one must hold the tunnel.
	snap := st.Snapshot()
	if st.Get() != StateReady || snap.CurrentExitIP != "3.3.3.3" {
		t.Fatalf("retry must leave the pod Ready on the fresh exit: state=%s snapshot=%+v", st.Get(), snap)
	}
	fresh := snap.CurrentLocation
	burnt := "Canada"
	if fresh == "Canada" {
		burnt = "USA"
	}
	if !blocked.cooledLocation(burnt) || !blocked.cooledCountry(currentCountry(burnt)) {
		t.Fatalf("a rotation into the same /24 must cool %s", burnt)
	}
	if blocked.cooledLocation(fresh) {
		t.Fatalf("%s served a fresh prefix and must not be cooled", fresh)
	}
	// Three connects in all: the first rotation (USA), the burnt
	// attempt, the retry — USA twice and Canada once whichever way
	// the second rotation started.
	if sp.attemptCount() != 3 || sp.callsByLocation["USA"] != 2 || sp.callsByLocation["Canada"] != 1 {
		t.Fatalf("burnt prefix must be retried elsewhere: attempts=%d calls=%v", sp.attemptCount(), sp.callsByLocation)
	}
}

func TestConnectWithRetryKeepsBurntExitOnLastAttempt(t *testing.T) {
	prevB, prevE, prevP := blocked, exits, pref
	t.Cleanup(func() { blocked, exits, pref = prevB, prevE, prevP })
	blocked, _ = newTestCooldown(time.Hour)
	exits = newExitMemory(time.Hour)
	pref = nil

	sp := newScriptedProvider([]string{"USA"}, []bool{true, true}, []string{"2.2.2.2", "2.2.2.9"})
	st := NewStateTracker("scripted")
	ns := &noSleep{}
	for i := 0; i < 2; i++ {
		if err := connectWithRetry(context.Background(), sp, st, "scripted", nil, 1, ns.sleep, ""); err != nil {
			t.Fatalf("rotation %d: %v", i+1, err)
		}
	}
	if !blocked.cooledLocation("USA") {
		t.Fatal("the repeat still cools USA")
	}
	if snap := st.Snapshot(); st.Get() != StateReady || snap.CurrentExitIP != "2.2.2.9" {
		t.Fatalf("with no attempt left the burnt exit is kept: state=%s snapshot=%+v", st.Get(), snap)
	}
}

func TestFallbackPickSkipsCooledLocations(t *testing.T) {
	prev := blocked
	t.Cleanup(func() { blocked = prev })
	blocked, _ = newTestCooldown(time.Hour)
	blocked.mark("Toronto", "")
	for i := 0; i < 50; i++ {
		loc, _, err := pickPreferredLocation(nil, []string{"Toronto", "Vancouver"}, nil)
		if err != nil || loc != "Vancouver" {
			t.Fatalf("pick = (%q, %v), want Vancouver", loc, err)
		}
	}
	// Everything cooled: the cool-down is ignored, never a failure.
	blocked.mark("Vancouver", "")
	if loc, _, err := pickPreferredLocation(nil, []string{"Toronto", "Vancouver"}, nil); err != nil || loc == "" {
		t.Fatalf("all-cooled pick = (%q, %v)", loc, err)
	}
}

func TestExitMemoryRefusedOutlivesTheUsedMemory(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	m := newExitMemoryWithRefused(time.Hour, 24*time.Hour)
	m.now = func() time.Time { return now }
	if !m.refuse("5.5.5.5") || !m.isRefused("5.5.5.200") || m.isRefused("5.5.6.1") {
		t.Fatal("a refusal covers the /24 and only the /24")
	}
	if !m.remember("5.5.5.9") {
		t.Fatal("a rotation into a refused prefix is a repeat even on first use")
	}
	now = now.Add(2 * time.Hour)
	if !m.remember("5.5.5.9") {
		t.Fatal("the refusal outlives the one-hour used-exit memory")
	}
	if m.refusedSize() != 1 {
		t.Fatalf("refusedSize = %d, want 1", m.refusedSize())
	}
	now = now.Add(23 * time.Hour)
	if m.isRefused("5.5.5.5") || m.refusedSize() != 0 {
		t.Fatal("a refusal expires after refusedTTL")
	}
	if m.remember("5.5.5.5") {
		t.Fatal("after expiry the prefix is fresh again")
	}
	off := newExitMemoryWithRefused(0, 24*time.Hour)
	if !off.refuse("6.6.6.6") || !off.remember("6.6.6.1") || off.remember("7.7.7.7") || off.remember("7.7.7.7") {
		t.Fatal("a disabled used-exit memory still honours refusals and never repeats otherwise")
	}
	none := newExitMemoryWithRefused(time.Hour, 0)
	if none.refuse("8.8.8.8") || none.isRefused("8.8.8.8") {
		t.Fatal("refusedTTL 0 disables the refused memory")
	}
	var nilMem *exitMemory
	if nilMem.refuse("1.1.1.1") || nilMem.isRefused("1.1.1.1") || nilMem.refusedSize() != 0 {
		t.Fatal("nil memory is inert")
	}
}

func TestRotateHandlerBannedRefusesTheExitAndCoolsItsPool(t *testing.T) {
	prevB, prevE, prevP := blocked, exits, pref
	t.Cleanup(func() { blocked, exits, pref = prevB, prevE, prevP })
	blocked, _ = newTestCooldown(time.Hour)
	exits = newExitMemoryWithRefused(time.Hour, 24*time.Hour)
	pref = nil

	st := NewStateTracker("fake")
	st.RecordTunnelUp("Belgium", "9.9.9.9")
	st.RecordCountry("BE", "BE")
	st.Set(StateReady)
	triggered := make(chan struct{}, 1)
	h := rotateHandler(st, func() { triggered <- struct{}{} })

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/rotate?reason=banned", nil))
	<-triggered
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rr.Code)
	}
	if !exits.isRefused("9.9.9.42") {
		t.Fatal("reason=banned must put the exit's /24 into the refused memory")
	}
	if !blocked.cooledLocation("Belgium") || !blocked.cooledCountry("BE") {
		t.Fatal("reason=banned must cool the location and country the refused exit came from")
	}
	if exits.size() != 0 {
		t.Fatalf("a refusal is not a use: used prefixes = %d, want 0", exits.size())
	}
}

func TestConnectWithRetryAvoidsARefusedPrefix(t *testing.T) {
	prevB, prevE, prevP := blocked, exits, pref
	t.Cleanup(func() { blocked, exits, pref = prevB, prevE, prevP })
	blocked, _ = newTestCooldown(time.Hour)
	exits = newExitMemoryWithRefused(0, 24*time.Hour) // used-exit memory off: only the refusal can trip the retry
	pref = nil

	// First rotation lands on 2.2.2.2 and the crawler reports it banned.
	// The next rotation is handed 2.2.2.9 (same /24) and must retry past
	// it onto 3.3.3.3.
	sp := newScriptedProvider([]string{"USA", "Canada"}, []bool{true, true, true}, []string{"2.2.2.2", "2.2.2.9", "3.3.3.3"})
	st := NewStateTracker("scripted")
	ns := &noSleep{}
	if err := connectWithRetry(context.Background(), sp, st, "scripted", []string{"Canada"}, 3, ns.sleep, ""); err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	if !noteRefusedExit("USA", "US", "2.2.2.2") {
		t.Fatal("refusal must be recorded")
	}
	if err := connectWithRetry(context.Background(), sp, st, "scripted", nil, 3, ns.sleep, ""); err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	if snap := st.Snapshot(); st.Get() != StateReady || snap.CurrentExitIP != "3.3.3.3" {
		t.Fatalf("the rotation must retry past the refused prefix: state=%s snapshot=%+v", st.Get(), snap)
	}
	if sp.attemptCount() != 3 {
		t.Fatalf("attempts = %d, want 3 (first rotation, refused landing, retry)", sp.attemptCount())
	}
}
