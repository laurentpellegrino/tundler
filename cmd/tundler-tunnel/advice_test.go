package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func newTestAdvised() (*advisedLocations, *time.Time) {
	now := time.Unix(1_770_000_000, 0)
	a := newAdvisedLocations()
	a.now = func() time.Time { return now }
	return a, &now
}

// withAdvised installs a fresh list (and the memories the picks read)
// for the test.
func withAdvised(t *testing.T) *advisedLocations {
	t.Helper()
	prevA, prevB, prevE, prevP := advised, blocked, exits, pref
	t.Cleanup(func() { advised, blocked, exits, pref = prevA, prevB, prevE, prevP })
	advised = newAdvisedLocations()
	blocked, _ = newTestCooldown(time.Hour)
	exits = newExitMemory(time.Hour)
	pref = nil
	return advised
}

func rotatePost(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/rotate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestAdvisedLocationsSetSkipExpireAndClear(t *testing.T) {
	a, now := newTestAdvised()
	if a.skip("Peru") || a.count() != 0 {
		t.Fatal("an empty list skips nothing")
	}
	if kept := a.set([]string{"Peru", " Laos ", "", "   ", strings.Repeat("x", maxAdvisedNameBytes+1), "Peru"}); kept != 2 {
		t.Fatalf("kept %d names, want 2: blank, oversize and repeated names are dropped", kept)
	}
	if !a.skip("Peru") || !a.skip("Laos") || a.skip("Chile") {
		t.Fatal("only the named locations are skipped")
	}
	got := a.list()
	slices.Sort(got)
	if !slices.Equal(got, []string{"Laos", "Peru"}) || a.count() != 2 {
		t.Fatalf("list = %v, count = %d", got, a.count())
	}
	// The list is advice for one rotation: it lapses on its own.
	*now = now.Add(advisedTTL)
	if a.skip("Peru") || a.count() != 0 || len(a.list()) != 0 {
		t.Fatal("the list must lapse after its lifetime")
	}
	a.set([]string{"Peru"})
	a.clear()
	if a.skip("Peru") {
		t.Fatal("clear drops the list")
	}
	a.set([]string{"Peru"})
	if kept := a.set(nil); kept != 0 || a.skip("Peru") {
		t.Fatal("a request without a list drops the previous one")
	}
	many := make([]string, maxAdvisedLocations+50)
	for i := range many {
		many[i] = fmt.Sprintf("location-%d", i)
	}
	if kept := a.set(many); kept != maxAdvisedLocations {
		t.Fatalf("kept %d names, want the cap %d", kept, maxAdvisedLocations)
	}
	var none *advisedLocations
	if none.set([]string{"Peru"}) != 0 || none.skip("Peru") || none.count() != 0 || none.list() != nil {
		t.Fatal("a nil list is inert")
	}
	none.clear()
}

func TestRotateHandlerStoresTheListOnlyWhenARotationStarts(t *testing.T) {
	a := withAdvised(t)
	st := NewStateTracker("fake")
	st.RecordTunnelUp("Belgium", "1.2.3.4")
	st.Set(StateReady)
	triggered := make(chan struct{}, 1)
	h := rotateHandler(st, func() { triggered <- struct{}{} })

	rr := httptest.NewRecorder()
	h(rr, rotatePost(`{"reason":"blocked","avoid_locations":["Peru","Laos"]}`))
	<-triggered
	if rr.Code != http.StatusAccepted || !a.skip("Peru") || !a.skip("Laos") || a.count() != 2 {
		t.Fatalf("status = %d, list = %v: a request that starts a rotation stores its list", rr.Code, a.list())
	}

	// Debounced: nothing is picked, so the list in force is left alone.
	st.RecordRotation("1.2.3.4", "5.6.7.8", "success", time.Second)
	rr = httptest.NewRecorder()
	h(rr, rotatePost(`{"reason":"blocked","avoid_locations":["Chile"]}`))
	if rr.Code != http.StatusOK || a.skip("Chile") || !a.skip("Peru") {
		t.Fatalf("status = %d, list = %v: a debounced request must not change the list", rr.Code, a.list())
	}

	// Not Ready: nothing is picked either.
	st.Set(StateRotating)
	rr = httptest.NewRecorder()
	h(rr, rotatePost(`{"avoid_locations":["Chile"]}`))
	if a.skip("Chile") {
		t.Fatal("a request during a rotation must not change the list")
	}
}

func TestRotateHandlerWithoutAListDropsThePreviousOne(t *testing.T) {
	a := withAdvised(t)
	a.set([]string{"Peru"})
	st := NewStateTracker("fake")
	st.RecordTunnelUp("Belgium", "1.2.3.4")
	st.Set(StateReady)
	triggered := make(chan struct{}, 1)
	h := rotateHandler(st, func() { triggered <- struct{}{} })
	rr := httptest.NewRecorder()
	h(rr, rotatePost(`{"reason":"blocked"}`))
	<-triggered
	if rr.Code != http.StatusAccepted || a.count() != 0 {
		t.Fatalf("status = %d, list = %v: the body of older callers still works and carries no list", rr.Code, a.list())
	}
}

func TestReadRotateRequest(t *testing.T) {
	req := readRotateRequest(rotatePost(`{"reason":" Banned ","avoid_locations":["Peru"]}`))
	if req.Reason != "banned" || !slices.Equal(req.Avoid, []string{"Peru"}) {
		t.Fatalf("req = %+v", req)
	}
	// The query parameter wins for the reason and the body still gives the list.
	q := httptest.NewRequest(http.MethodPost, "/rotate?reason=Blocked", strings.NewReader(`{"reason":"banned","avoid_locations":["Laos"]}`))
	if req := readRotateRequest(q); req.Reason != "blocked" || !slices.Equal(req.Avoid, []string{"Laos"}) {
		t.Fatalf("req = %+v", req)
	}
	for name, body := range map[string]string{
		"malformed":  `{"reason":"blocked","avoid_locations":["Peru"`,
		"wrong type": `{"reason":"blocked","avoid_locations":"Peru"}`,
		"oversize":   `{"reason":"blocked","avoid_locations":["` + strings.Repeat("x", maxRotateBody) + `"]}`,
		"empty":      ``,
	} {
		if req := readRotateRequest(rotatePost(body)); req.Reason != "" || len(req.Avoid) != 0 {
			t.Fatalf("%s body: req = %+v, want nothing", name, req)
		}
	}
	if req := readRotateRequest(httptest.NewRequest(http.MethodPost, "/rotate", nil)); req.Reason != "" || req.Avoid != nil {
		t.Fatalf("no body: req = %+v", req)
	}
}

func TestRegionWalkSkipsAdvisedLocations(t *testing.T) {
	p := newStridedPref(0, 1)
	p.dwellCap = 10
	p.advised, _ = newTestAdvised()
	catalog := []string{"de-berlin", "de-frankfurt", "de-munich"}
	p.advised.set([]string{"de-berlin"})
	for i := 0; i < 30; i++ {
		if loc, _, _ := p.pick(catalog, nil); loc == "de-berlin" {
			t.Fatal("pick returned a location the rotation request named")
		}
	}
	// A country named in full: the walk looks at its next country.
	p.advised.set(catalog)
	if loc, cc, ok := p.pick(append(slices.Clone(catalog), "fr-paris"), nil); !ok || loc != "fr-paris" || cc != "FR" {
		t.Fatalf("pick = (%q, %q, %v), want fr-paris", loc, cc, ok)
	}
	// A catalog named in full: a named location beats no location.
	if loc, _, ok := p.pick(catalog, nil); !ok || loc == "" {
		t.Fatalf("fully named pick = (%q, %v)", loc, ok)
	}
}

func TestFallbackPickSkipsAdvisedLocations(t *testing.T) {
	a := withAdvised(t)
	a.set([]string{"Toronto"})
	for i := 0; i < 50; i++ {
		loc, _, err := pickPreferredLocation(nil, []string{"Toronto", "Vancouver"}, nil)
		if err != nil || loc != "Vancouver" {
			t.Fatalf("pick = (%q, %v), want Vancouver", loc, err)
		}
	}
	a.set([]string{"Toronto", "Vancouver"})
	if loc, _, err := pickPreferredLocation(nil, []string{"Toronto", "Vancouver"}, nil); err != nil || loc == "" {
		t.Fatalf("fully named pick = (%q, %v)", loc, err)
	}
}

func TestTheListIsDroppedWhenATunnelComesUpAndKeptWhenTheRotationFails(t *testing.T) {
	a := withAdvised(t)
	// The rotation goes to the one location not named, fails there, and
	// the watchdog reconnect that follows still knows the list.
	sp := newScriptedProvider([]string{"USA", "Canada"}, []bool{false, true}, []string{"", "3.3.3.3"})
	st := NewStateTracker("scripted")
	ns := &noSleep{}
	a.set([]string{"USA"})
	if err := connectWithRetry(context.Background(), sp, st, "scripted", nil, 1, ns.sleep, ""); err == nil {
		t.Fatal("attempt 1 is scripted to fail")
	}
	if sp.callsByLocation["USA"] != 0 || !a.skip("USA") {
		t.Fatalf("calls = %v, list = %v: the named location must be skipped and the list kept after a failure", sp.callsByLocation, a.list())
	}
	if _, err := connectTunnelAt(context.Background(), sp, st, "scripted", nil, ""); err != nil {
		t.Fatalf("watchdog reconnect: %v", err)
	}
	if a.count() != 0 {
		t.Fatalf("list = %v: a tunnel that came up ends the advice", a.list())
	}
	// Same on the rotation path (with a fresh exit memory: Canada's
	// exit above would otherwise make it a spent location).
	exits = newExitMemory(time.Hour)
	a.set([]string{"USA"})
	sp = newScriptedProvider([]string{"USA", "Canada"}, []bool{true}, []string{"4.4.4.4"})
	if err := connectWithRetry(context.Background(), sp, st, "scripted", nil, 1, ns.sleep, ""); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if sp.callsByLocation["USA"] != 0 || a.count() != 0 {
		t.Fatalf("calls = %v, list = %v", sp.callsByLocation, a.list())
	}
}

func TestStatusReportsAdvisedLocations(t *testing.T) {
	a := withAdvised(t)
	st := NewStateTracker("fake")
	st.Set(StateReady)
	read := func() map[string]any {
		rr := httptest.NewRecorder()
		statusHandler(st, "", "", BrowserIdentity{})(rr, httptest.NewRequest(http.MethodGet, "/status", nil))
		var snap map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return snap
	}
	// Present even at zero: its presence tells a caller the field is read.
	if v, ok := read()["advised_locations"]; !ok || v != float64(0) {
		t.Fatalf("advised_locations = %v (present %v), want 0", v, ok)
	}
	a.set([]string{"Peru", "Laos"})
	if v := read()["advised_locations"]; v != float64(2) {
		t.Fatalf("advised_locations = %v, want 2", v)
	}
}
