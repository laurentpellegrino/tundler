package geo

import (
	"testing"
	"time"
)

// TestGuessAlpha2 exercises the heuristic against real samples of every
// provider vocabulary in the fleet.
func TestGuessAlpha2(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		// Rule 1 — bare codes.
		{"DE", "DE", true}, // PureVPN
		{"de", "DE", true}, // TunnelBear
		{"UK", "GB", true}, // FastVPN/IPVanish catalogs
		{"uk", "GB", true}, // TunnelBear
		{"gb", "GB", true}, // ISO-correct input
		{"xx", "", false},  // unknown code
		{"a", "", false},   // too short
		{"", "", false},    // empty
		{"  se ", "SE", true},

		// Rule 2 — cc-city slugs (PIA).
		{"de-berlin", "DE", true},
		{"de-frankfurt", "DE", true},
		{"us-chicago", "US", true},
		{"us_chicago", "US", true},
		{"uk-london", "GB", true},
		{"zz-nowhere", "", false},

		// Rule 3 — country names.
		{"Germany", "DE", true},                         // NordVPN, mullvad, proton, ...
		{"United_States", "US", true},                   // NordVPN
		{"United States", "US", true},                   // country-name catalogs
		{"united states", "US", true},                   // case-insensitive
		{"Czech Republic", "CZ", true},                  // canonical
		{"Czechia", "CZ", true},                         // alias
		{"North Macedonia", "MK", true},                 // canonical
		{"Macedonia", "MK", true},                       // legacy fastvpn table name
		{"Macau", "MO", true},                           // legacy ipvanish table name
		{"South Korea", "KR", true},                     // canonical
		{"Lao_Peoples_Democratic_Republic", "LA", true}, // NordVPN
		{"Cote d'Ivoire", "CI", true},                   // proton exclusion-list spelling
		{"Bosnia and Herzegovina", "BA", true},
		{"United Kingdom", "GB", true},
		{"Russian Federation", "RU", true},

		// Rule 3 with hyphens (ExpressVPN multi-word countries).
		{"czech-republic", "CZ", true},
		{"bosnia-and-herzegovina", "BA", true},
		{"united-arab-emirates", "AE", true},
		{"isle-of-man", "IM", true},

		// Rule 4 — "country-city[-n]" slugs (ExpressVPN).
		{"usa-new-york", "US", true},
		{"usa-st.-louis", "US", true},
		{"usa-charleston-west-virginia", "US", true},
		{"germany-frankfurt-1", "DE", true},
		{"france-paris-2", "FR", true},
		{"netherlands-the-hague", "NL", true},
		{"canada-toronto-2", "CA", true},
		{"australia-woolloomooloo", "AU", true},
		{"japan-shibuya", "JP", true},
		{"hong-kong-1", "HK", true},
		{"south-korea-2", "KR", true},
		{"singapore-marina-bay", "SG", true},
		{"spain-barcelona-2", "ES", true},
		{"taiwan-3", "TW", true},
		{"sweden-2", "SE", true},
		{"india-(via-uk)", "IN", true},
		{"gaming-europe", "", false}, // no country prefix

		// Unmappable — never preferred, still connectable.
		{"Toronto", "", false},     // Windscribe city
		{"Vancouver", "", false},   // Windscribe city
		{"Jersey City", "", false}, // spaces: rule 4 must not make it JE
		{"auto", "", false},        // warp/psiphon pseudo-location
		{"[smart]", "", false},     // expressvpn placeholder
	}
	for _, c := range cases {
		got, ok := GuessAlpha2(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("GuessAlpha2(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCountryNameAliases(t *testing.T) {
	// The fastvpn/ipvanish call sites look up the literal "UK" from
	// upstream config filenames; the alias must keep that working.
	if n, ok := CountryName("UK"); !ok || n != "United Kingdom" {
		t.Fatalf("CountryName(UK) = (%q, %v), want (United Kingdom, true)", n, ok)
	}
	if n, ok := CountryName("de"); !ok || n != "Germany" {
		t.Fatalf("CountryName(de) = (%q, %v), want (Germany, true)", n, ok)
	}
	if _, ok := CountryName("ZZ"); ok {
		t.Fatal("CountryName(ZZ) should be unknown")
	}
}

func TestAlpha2FromNameNormalization(t *testing.T) {
	for _, in := range []string{"germany", "GERMANY", "Germany", " Germany "} {
		if code, ok := Alpha2FromName(in); !ok || code != "DE" {
			t.Errorf("Alpha2FromName(%q) = (%q, %v), want (DE, true)", in, code, ok)
		}
	}
}

// TestPreferredOrderDeterministicPermutation asserts every pod derives
// the identical ordering for an epoch (determinism) and that the
// ordering is a true permutation of the country universe.
func TestPreferredOrderDeterministicPermutation(t *testing.T) {
	const epoch = 20678 // arbitrary
	a, b := PreferredOrder(epoch), PreferredOrder(epoch)
	if len(a) != len(b) || len(a) == 0 {
		t.Fatalf("lengths differ or empty: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("orderings diverge at %d: %s vs %s", i, a[i], b[i])
		}
	}

	seen := make(map[string]bool, len(a))
	for _, c := range a {
		if seen[c] {
			t.Fatalf("duplicate %s in ordering", c)
		}
		seen[c] = true
	}
	for _, c := range AllAlpha2() {
		if !seen[c] {
			t.Fatalf("country %s missing from ordering", c)
		}
	}

	// Different epochs explore different permutations (astronomically
	// unlikely to be identical if the seed is actually used).
	c := PreferredOrder(epoch + 1)
	same := true
	for i := range a {
		if a[i] != c[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("epoch+1 produced the identical permutation")
	}
}

func TestEpochBoundaries(t *testing.T) {
	day := int64(24 * 60 * 60)
	if e0, e1 := Epoch(time.Unix(0, 0)), Epoch(time.Unix(day-1, 0)); e0 != e1 {
		t.Fatalf("same day split epochs: %d vs %d", e0, e1)
	}
	if e1, e2 := Epoch(time.Unix(day-1, 0)), Epoch(time.Unix(day, 0)); e1 == e2 {
		t.Fatal("midnight boundary did not advance the epoch")
	}
}
