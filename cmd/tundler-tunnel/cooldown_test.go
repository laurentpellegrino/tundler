package main

import (
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

func TestRotateHandlerBlockedReasonCoolsCurrentLocation(t *testing.T) {
	prev := blocked
	t.Cleanup(func() { blocked = prev })
	blocked, _ = newTestCooldown(time.Hour)

	st := NewStateTracker("fake")
	st.RecordTunnelUp("Belgium", "1.2.3.4")
	st.RecordCountry("BE", "BE")
	st.Set(StateReady)
	triggered := make(chan struct{}, 1)
	h := rotateHandler(st, func() { triggered <- struct{}{} })

	// Plain call: nothing learnt.
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/rotate", nil))
	<-triggered
	if blocked.cooledLocation("Belgium") {
		t.Fatal("a /rotate without reason must not cool the location")
	}

	// JSON body reason.
	st.Set(StateReady)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rotate", strings.NewReader(`{"reason":"blocked"}`))
	req.Header.Set("Content-Type", "application/json")
	h(rr, req)
	if rr.Code != http.StatusAccepted && rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if !blocked.cooledLocation("Belgium") || !blocked.cooledCountry("BE") {
		t.Fatal("reason=blocked must cool the current location and country")
	}

	// Query parameter works too and an unknown reason is ignored.
	blocked, _ = newTestCooldown(time.Hour)
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/rotate?reason=curious", nil))
	if blocked.cooledLocation("Belgium") {
		t.Fatal("unknown reason must be ignored")
	}
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/rotate?reason=Blocked", nil))
	if !blocked.cooledLocation("Belgium") {
		t.Fatal("query reason must cool the location")
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
