package main

import (
	"testing"
	"time"
)

// fixedNow pins the epoch so every subtest shares one country ordering.
var fixedNow = func() time.Time { return time.Unix(1_770_000_000, 0) }

// newTestPref models pod `slot` of a single provider block that spans
// the whole fleet (base 0, ordinal = slot).
func newTestPref(slot, slots int) *locationPreference {
	return &locationPreference{base: 0, ordinal: slot, slot: slot, slots: slots, now: fixedNow}
}

// multiCountryCatalog is a provider offering a handful of mappable
// countries in NordVPN-ish vocabulary plus unmappable noise.
var multiCountryCatalog = []string{
	"Germany", "Sweden", "Japan", "Brazil", "Canada",
	"Netherlands", "United_States", "auto",
}

func TestPickSiblingsTakeDistinctCountries(t *testing.T) {
	// With as many pods as countries on offer (7 mappable entries in
	// the catalog), every sibling must land on its own country: pods
	// index the ring-ordered offered list by ordinal, so collisions
	// only happen once the catalog runs out.
	seen := map[string]bool{}
	for ordinal := 0; ordinal < 7; ordinal++ {
		_, cc, ok := newTestPref(ordinal, 7).pick(multiCountryCatalog, nil)
		if !ok {
			t.Fatalf("ordinal %d: no preferred country", ordinal)
		}
		seen[cc] = true
	}
	if len(seen) != 7 {
		t.Fatalf("7 siblings landed on %d countries (%v) — want 7 distinct", len(seen), seen)
	}
	// One more pod than countries wraps onto the first pick.
	_, first, _ := newTestPref(0, 8).pick(multiCountryCatalog, nil)
	_, eighth, _ := newTestPref(7, 8).pick(multiCountryCatalog, nil)
	if first != eighth {
		t.Fatalf("ordinal 7 of 8 should wrap onto ordinal 0's country %q, got %q", first, eighth)
	}
}

func TestPickSparseCatalogStillSpreads(t *testing.T) {
	// The production case that motivated the ordinal index: a provider
	// block of 7 adjacent fleet slots (base 26 of 81) over a catalog of
	// 17 countries drawn from a 146-country ring. Walking the full ring
	// from each slot collapsed them onto 2 countries.
	catalog := []string{"AT", "CA", "CH", "DE", "DK", "ES", "FI", "FR", "GB", "IT", "NL", "NO", "PL", "RO", "SE", "UA", "US"}
	seen := map[string]bool{}
	for ordinal := 0; ordinal < 7; ordinal++ {
		p := &locationPreference{base: 26, ordinal: ordinal, slot: 26 + ordinal, slots: 81, now: fixedNow}
		_, cc, ok := p.pick(catalog, nil)
		if !ok {
			t.Fatalf("ordinal %d: no preferred country", ordinal)
		}
		seen[cc] = true
	}
	if len(seen) != 7 {
		t.Fatalf("7 siblings over 17 countries landed on %d (%v)", len(seen), seen)
	}
}

func TestPickDeterministicPerSlot(t *testing.T) {
	p := newTestPref(2, 5)
	_, cc1, ok1 := p.pick(multiCountryCatalog, nil)
	_, cc2, ok2 := p.pick(multiCountryCatalog, nil)
	if !ok1 || !ok2 || cc1 != cc2 {
		t.Fatalf("same slot+epoch+steps must pick the same country: %q vs %q", cc1, cc2)
	}
}

func TestPickSkipsFullyExcludedCountry(t *testing.T) {
	// Excluding every location of a country removes it from the walk.
	catalog := []string{"Germany", "Sweden"}
	for slot := 0; slot < 4; slot++ {
		loc, cc, ok := newTestPref(slot, 4).pick(catalog, []string{"Germany"})
		if !ok || cc != "SE" || loc != "Sweden" {
			t.Fatalf("slot %d: pick = (%q, %q, %v), want Sweden/SE", slot, loc, cc, ok)
		}
	}
}

func TestPickSingleCountryConverges(t *testing.T) {
	// Soft-preference correctness: when the provider offers ONE
	// country, every pod takes it — same region beats no region.
	for slot := 0; slot < 5; slot++ {
		loc, cc, ok := newTestPref(slot, 5).pick([]string{"de-berlin", "de-frankfurt"}, nil)
		if !ok || cc != "DE" || (loc != "de-berlin" && loc != "de-frankfurt") {
			t.Fatalf("slot %d: pick = (%q, %q, %v)", slot, loc, cc, ok)
		}
	}
}

func TestPickUnmappableCatalogFallsBack(t *testing.T) {
	// City-name catalogs (Windscribe) and "auto" never map — ok=false
	// tells the caller to use the legacy random pick.
	if _, _, ok := newTestPref(0, 2).pick([]string{"Toronto", "Vancouver", "auto"}, nil); ok {
		t.Fatal("unmappable catalog should not be preferred")
	}
	// And pickPreferredLocation then still yields a location.
	loc, cc, err := pickPreferredLocation(newTestPref(0, 2), []string{"Toronto", "Vancouver"}, nil)
	if err != nil || loc == "" || cc != "" {
		t.Fatalf("fallback = (%q, %q, %v)", loc, cc, err)
	}
}

func TestAdvanceShiftsPick(t *testing.T) {
	p := newTestPref(0, 1)
	_, before, _ := p.pick(multiCountryCatalog, nil)
	changed := false
	// Each advance moves to the next OFFERED country, so the pick
	// changes on the first step; the loop bound is just slack.
	for i := 0; i < 300 && !changed; i++ {
		p.advance()
		if _, after, _ := p.pick(multiCountryCatalog, nil); after != before {
			changed = true
		}
	}
	if !changed {
		t.Fatal("advance() never moved the pick across a full ring traversal")
	}
}

func TestNilPreferenceUsesLegacyPick(t *testing.T) {
	loc, cc, err := pickPreferredLocation(nil, []string{"Germany", "Sweden"}, nil)
	if err != nil || loc == "" || cc != "" {
		t.Fatalf("nil pref = (%q, %q, %v)", loc, cc, err)
	}
}

func TestNewLocationPreferenceFromEnv(t *testing.T) {
	t.Setenv("POD_NAME", "tundler-tunnel-x-2")

	t.Setenv("TUNDLER_FLEET_SLOT_BASE", "")
	t.Setenv("TUNDLER_FLEET_SLOTS", "")
	if newLocationPreferenceFromEnv() != nil {
		t.Fatal("unset env must disable the preference")
	}

	t.Setenv("TUNDLER_FLEET_SLOT_BASE", "10")
	t.Setenv("TUNDLER_FLEET_SLOTS", "20")
	p := newLocationPreferenceFromEnv()
	if p == nil || p.slot != 12 || p.slots != 20 || p.base != 10 || p.ordinal != 2 {
		t.Fatalf("pref = %+v, want slot 12 (base 10 + ordinal 2) of 20", p)
	}

	// Slot outside the fleet range: disabled, not fatal.
	t.Setenv("TUNDLER_FLEET_SLOTS", "11")
	if newLocationPreferenceFromEnv() != nil {
		t.Fatal("out-of-range slot must disable the preference")
	}
}

// newStridedPref models pod `ordinal` of a provider with `replicas`
// pods whose block spans the whole fleet.
func newStridedPref(ordinal, replicas int) *locationPreference {
	return &locationPreference{base: 0, ordinal: ordinal, slot: ordinal, slots: replicas, replicas: replicas, now: fixedNow}
}

// bigCatalog is 30 mappable countries in alpha-2 vocabulary.
var bigCatalog = []string{
	"AR", "AT", "AU", "BE", "BG", "BR", "CA", "CH", "CL", "CZ",
	"DE", "DK", "EE", "ES", "FI", "FR", "GB", "GR", "HR", "HU",
	"IE", "IT", "JP", "LT", "LU", "LV", "MX", "NL", "NO", "PL",
}

func TestStridedWalkNeverCollidesAcrossRotationHistories(t *testing.T) {
	// 8 pods, 30 countries, stride 8: whatever each pod's rotation
	// count, no two siblings share a country — the failure seen on
	// 2026-10-20 with stride 1 (5 of 8 ExpressVPN pods in Belgium).
	const pods = 8
	for trial := 0; trial < 200; trial++ {
		seen := map[string]int{}
		for ordinal := 0; ordinal < pods; ordinal++ {
			p := newStridedPref(ordinal, pods)
			for s := 0; s < (trial*7+ordinal*3)%40; s++ {
				p.advance()
			}
			_, cc, ok := p.pick(bigCatalog, nil)
			if !ok {
				t.Fatalf("ordinal %d: no pick", ordinal)
			}
			if other, dup := seen[cc]; dup {
				t.Fatalf("trial %d: ordinals %d and %d both on %s", trial, other, ordinal, cc)
			}
			seen[cc] = ordinal
		}
	}
}

func TestStrideOneReproducesCollision(t *testing.T) {
	// Sanity check that the test above is meaningful: with stride 1,
	// pod 0 after one rotation sits where pod 1 started.
	p0 := &locationPreference{ordinal: 0, slots: 8, replicas: 1, now: fixedNow}
	p1 := &locationPreference{ordinal: 1, slot: 1, slots: 8, replicas: 1, now: fixedNow}
	p0.advance()
	_, a, _ := p0.pick(bigCatalog, nil)
	_, b, _ := p1.pick(bigCatalog, nil)
	if a != b {
		t.Fatalf("stride 1 should collide here: %s vs %s", a, b)
	}
}

func TestStridedWalkCoversItsClass(t *testing.T) {
	// 30 countries / 8 pods → span 24, 3 positions per pod; a pod
	// cycles through exactly its 3 countries.
	p := newStridedPref(2, 8)
	seen := map[string]bool{}
	for s := 0; s < 9; s++ {
		_, cc, _ := p.pick(bigCatalog, nil)
		seen[cc] = true
		p.advance()
	}
	if len(seen) != 3 {
		t.Fatalf("pod cycled %d countries (%v), want 3", len(seen), seen)
	}
}

func TestStridedWalkFewerCountriesThanPods(t *testing.T) {
	// 7 pods over 5 countries: sharing is unavoidable, but every pod
	// still gets a pick and the walk still moves.
	catalog := []string{"DE", "SE", "JP", "BR", "CA"}
	for ordinal := 0; ordinal < 7; ordinal++ {
		p := newStridedPref(ordinal, 7)
		_, before, ok := p.pick(catalog, nil)
		p.advance()
		_, after, ok2 := p.pick(catalog, nil)
		if !ok || !ok2 || before == after {
			t.Fatalf("ordinal %d: %q → %q (%v/%v)", ordinal, before, after, ok, ok2)
		}
	}
}

func TestCooledCountrySkipsWithinOwnClass(t *testing.T) {
	const pods = 8
	p := newStridedPref(3, pods)
	c, _ := newTestCooldown(time.Hour)
	p.cooldown = c
	_, first, _ := p.pick(bigCatalog, nil)
	c.mark("", first)
	_, second, _ := p.pick(bigCatalog, nil)
	if second == first {
		t.Fatal("a cooled country must be skipped")
	}
	// The replacement is a country the pod would reach by advancing,
	// i.e. still inside its own residue class — never a sibling's.
	q := newStridedPref(3, pods)
	q.advance()
	_, next, _ := q.pick(bigCatalog, nil)
	if second != next {
		t.Fatalf("skip went to %s, want the class's next position %s", second, next)
	}
	// Siblings are unaffected by this pod's cool-down.
	for ordinal := 0; ordinal < pods; ordinal++ {
		if ordinal == 3 {
			continue
		}
		if _, cc, _ := newStridedPref(ordinal, pods).pick(bigCatalog, nil); cc == second {
			t.Fatalf("sibling %d also on %s", ordinal, cc)
		}
	}
}

func TestCooledLocationSkipsWithinCountryThenCountry(t *testing.T) {
	p := newStridedPref(0, 1)
	c, _ := newTestCooldown(time.Hour)
	p.cooldown = c
	catalog := []string{"de-berlin", "de-frankfurt", "se-stockholm"}
	loc, cc, _ := p.pick(catalog, nil)
	if cc != "DE" && cc != "SE" {
		t.Fatalf("unexpected pick %s", cc)
	}
	c.mark(loc, "")
	for i := 0; i < 20; i++ {
		again, _, _ := p.pick(catalog, nil)
		if again == loc {
			t.Fatalf("cooled location %s picked again", loc)
		}
	}
	// Every location cooled: the cool-down is ignored, a pick remains.
	for _, l := range catalog {
		c.mark(l, "")
	}
	if _, _, ok := p.pick(catalog, nil); !ok {
		t.Fatal("all-cooled catalog must still yield a preferred pick")
	}
}

func TestNewLocationPreferenceReplicasEnv(t *testing.T) {
	t.Setenv("POD_NAME", "tundler-tunnel-x-2")
	t.Setenv("TUNDLER_FLEET_SLOT_BASE", "10")
	t.Setenv("TUNDLER_FLEET_SLOTS", "20")
	t.Setenv(envFleetReplicas, "")
	if p := newLocationPreferenceFromEnv(); p == nil || p.replicas != 1 {
		t.Fatalf("no replicas env → stride 1, got %+v", p)
	}
	t.Setenv(envFleetReplicas, "8")
	if p := newLocationPreferenceFromEnv(); p == nil || p.replicas != 8 {
		t.Fatalf("replicas env → stride 8, got %+v", p)
	}
	// An ordinal outside the replica count means the env is stale: stride 1.
	t.Setenv(envFleetReplicas, "2")
	if p := newLocationPreferenceFromEnv(); p == nil || p.replicas != 1 {
		t.Fatalf("stale replicas env → stride 1, got %+v", p)
	}
}
