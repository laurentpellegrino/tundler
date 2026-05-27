package main

import (
	"errors"
	"math/rand/v2"
	"strings"
)

// errNoAllowedLocations is returned by pickLocation when every location
// reported by the provider is in the excluded set (or the provider
// reported zero locations). The caller is expected to surface this as
// a fatal startup error — the pod has no usable location.
var errNoAllowedLocations = errors.New("no allowed locations after applying excluded_locations filter")

// pickLocation returns a uniformly random location from `locations`
// minus any matches in `excluded` (case-sensitive — same casing as the
// provider's own location names).
//
// excluded is normalized: empty strings and whitespace-only entries are
// dropped so an env var like "EXCLUDED_LOCATIONS=Bahrain,,Yemen, " still
// excludes exactly Bahrain and Yemen.
//
// Operators add known-bad exits to vpn-providers.yaml on the
// kubernetes side; the rendered env var arrives here as a CSV.
func pickLocation(locations []string, excluded []string) (string, error) {
	excludeSet := make(map[string]struct{}, len(excluded))
	for _, e := range excluded {
		e = strings.TrimSpace(e)
		if e != "" {
			excludeSet[e] = struct{}{}
		}
	}

	allowed := make([]string, 0, len(locations))
	for _, loc := range locations {
		if _, blocked := excludeSet[loc]; blocked {
			continue
		}
		allowed = append(allowed, loc)
	}

	if len(allowed) == 0 {
		return "", errNoAllowedLocations
	}
	return allowed[rand.IntN(len(allowed))], nil
}

// parseExcludedLocations parses a CSV env-var value into a slice. Empty
// string returns nil (no exclusions). Whitespace is trimmed.
func parseExcludedLocations(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
