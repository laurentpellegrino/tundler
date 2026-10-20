package geo

import "strings"

// GuessAlpha2 maps a provider Locations() entry to an ISO alpha-2
// country code, best-effort. One generic heuristic covers every
// mappable vocabulary in the fleet — no per-provider normalizers:
//
//  1. bare two-letter code, any case, code aliases applied
//     → PureVPN "DE", TunnelBear "de", catalogs saying "UK"
//  2. two-letter prefix followed by '-' or '_'
//     → PIA "de-berlin", "uk-london", "us_chicago"
//  3. full-string country-name lookup (case-insensitive, underscores
//     and hyphens as spaces, apostrophes ignored)
//     → NordVPN "United_States", ExpressVPN "czech-republic", and the
//     country-name catalogs (mullvad, protonvpn, surfshark, cyberghost,
//     ovpn, ipvanish, fastvpn, veepn)
//  4. hyphenated "country-city[-n]" slug: the longest hyphen-separated
//     prefix that is a country name
//     → ExpressVPN "usa-new-york", "germany-frankfurt-1",
//     "south-korea-2", "india-(via-uk)"
//
// Anything else returns ok=false: the location is simply never
// PREFERRED by the region-spread walk but remains fully connectable
// (Windscribe city names and the "auto" pseudo-location of
// warp/psiphon land here). Rule 4 is restricted to space-free slugs
// so a Windscribe "Jersey City" never becomes JE. Best-effort by design — a wrong "not
// mapped" costs nothing, so there are no error paths.
//
// If a future provider's vocabulary defeats this heuristic, add an
// optional `interface{ LocationCountry(string) (string, bool) }`
// asserted in cmd/tundler-tunnel/main.go BEFORE the provider is
// wrapped in cachedLocationsProvider (the wrapper would hide the
// assertion) — same pattern as the AttachProxy assertion there.
func GuessAlpha2(location string) (string, bool) {
	loc := strings.TrimSpace(location)
	if len(loc) < 2 {
		return "", false
	}

	// Rule 1: the whole string is a code.
	if len(loc) == 2 && isLetters(loc) {
		code := strings.ToUpper(loc)
		if iso, ok := codeAliases[code]; ok {
			code = iso
		}
		if _, known := countryNames[code]; known {
			return code, true
		}
		return "", false
	}

	// Rule 2: "cc-city" / "cc_city" region slugs.
	if len(loc) > 2 && (loc[2] == '-' || loc[2] == '_') && isLetters(loc[:2]) {
		code := strings.ToUpper(loc[:2])
		if iso, ok := codeAliases[code]; ok {
			code = iso
		}
		if _, known := countryNames[code]; known {
			return code, true
		}
		// A slug prefix that isn't a country code (e.g. a city pair)
		// still gets a chance as a full name in rule 3.
	}

	// Rule 3: the whole string is a country name.
	if code, ok := Alpha2FromName(loc); ok {
		return code, true
	}

	// Rule 4: "country-city[-n]" slug — longest country-name prefix on
	// hyphen boundaries. Rule 3 already tried the full string.
	if strings.Contains(loc, "-") && !strings.ContainsAny(loc, " \t") {
		fields := strings.Fields(normalizeName(loc))
		for n := len(fields) - 1; n >= 1; n-- {
			if code, ok := nameIndex[strings.Join(fields[:n], " ")]; ok {
				return code, true
			}
		}
	}
	return "", false
}

func isLetters(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}
