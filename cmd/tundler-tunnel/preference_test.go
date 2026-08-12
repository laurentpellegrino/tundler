package main

import (
	"testing"
	"time"
)

// fixedNow pins the epoch so every subtest shares one country ordering.
var fixedNow = func() time.Time { return time.Unix(1_770_000_000, 0) }

func newTestPref(slot, slots int) *locationPreference {
	return &locationPreference{slot: slot, slots: slots, now: fixedNow}
}

// multiCountryCatalog is a provider offering a handful of mappable
// countries in NordVPN-ish vocabulary plus unmappable noise.
var multiCountryCatalog = []string{
	"Germany", "Sweden", "Japan", "Brazil", "Canada",
	"Netherlands", "United_States", "auto",
}

func TestPickEvenSpreadStartsDiffer(t *testing.T) {
	// With as many slots as countries on offer, distinct slots must not
	// all converge on one country: the evenly-spaced starting offsets
	// should spread the picks. (Not every pair differs — ring walks can
	// land neighbors on the same country when the catalog is sparse —
	// but ALL landing identically would mean the offsets do nothing.)
	seen := map[string]bool{}
	for slot := 0; slot < 7; slot++ {
		_, cc, ok := newTestPref(slot, 7).pick(multiCountryCatalog, nil)
		if !ok {
			t.Fatalf("slot %d: no preferred country", slot)
		}
		seen[cc] = true
	}
	if len(seen) < 3 {
		t.Fatalf("7 slots collapsed onto %d countries (%v) — offsets not spreading", len(seen), seen)
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
	// One advance may land on a country the provider doesn't offer and
	// walk forward onto the same pick; a handful of rotations must
	// visit something new in a 7-country catalog.
	for i := 0; i < 5 && !changed; i++ {
		p.advance()
		if _, after, _ := p.pick(multiCountryCatalog, nil); after != before {
			changed = true
		}
	}
	if !changed {
		t.Fatal("advance() never moved the pick across 5 rotations")
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
	if p == nil || p.slot != 12 || p.slots != 20 {
		t.Fatalf("pref = %+v, want slot 12 (base 10 + ordinal 2) of 20", p)
	}

	// Slot outside the fleet range: disabled, not fatal.
	t.Setenv("TUNDLER_FLEET_SLOTS", "11")
	if newLocationPreferenceFromEnv() != nil {
		t.Fatal("out-of-range slot must disable the preference")
	}
}
