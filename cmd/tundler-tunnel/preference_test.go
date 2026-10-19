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
