package main

import (
	"errors"
	"log"
	"math/rand/v2"
	"strings"

	"github.com/laurentpellegrino/tundler/internal/geo"
)

// pref is the fleet region-spread preference, set once in main() before
// any goroutine connects (nil = feature off). Package state, matching
// the lastReloginUnix / recycleRotationLimit precedent — threading it
// through six call signatures buys nothing for a per-process singleton.
var pref *locationPreference

// blocked is the blocked-exit memory fed by POST /rotate?reason=blocked
// (see cooldown.go), set once in main() like pref. nil = no memory.
var blocked *locationCooldown

// exits remembers the exit IPs this pod used (see cooldown.go): a
// rotation landing on a remembered exit is the pool-exhausted signal.
var exits *exitMemory

// currentCountry best-effort maps the connected location to an ISO code
// for /status; "" when the vocabulary is unmappable (city names, auto).
func currentCountry(location string) string {
	cc, _ := geo.GuessAlpha2(location)
	return cc
}

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

// pickPreferredLocation applies the fleet region-spread preference when
// enabled (pref non-nil), falling back to the legacy uniform-random
// pickLocation — which stays untouched as the tested fallback — on any
// miss. Returns the chosen location plus the preferred ISO country
// ("" when the fallback won) for /status.
func pickPreferredLocation(pref *locationPreference, locations, excluded []string) (string, string, error) {
	// Failing locations (failinglocations.go) are skipped like excluded
	// ones; when that leaves nothing the holds are ignored rather than
	// failing the connect.
	if held := failing.held(); len(held) > 0 {
		withHeld := append(append([]string{}, excluded...), held...)
		if loc, country, err := pickUnheldLocation(pref, locations, withHeld); err == nil {
			return loc, country, nil
		}
		log.Printf("tundler-tunnel: every allowed location is excluded or held (%d held); ignoring the holds for this pick", len(held))
	}
	return pickUnheldLocation(pref, locations, excluded)
}

// pickUnheldLocation is pickPreferredLocation without the failing-location
// holds.
func pickUnheldLocation(pref *locationPreference, locations, excluded []string) (string, string, error) {
	if pref != nil {
		if loc, country, ok := pref.pick(locations, excluded); ok {
			return loc, country, nil
		}
	}
	// The random fallback skips cooling locations too; when that leaves
	// nothing the cool-down is ignored rather than failing the connect.
	if cooled := blocked.cooledLocations(); len(cooled) > 0 {
		if loc, err := pickLocation(locations, append(append([]string{}, excluded...), cooled...)); err == nil {
			return loc, "", nil
		}
	}
	loc, err := pickLocation(locations, excluded)
	return loc, "", err
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
