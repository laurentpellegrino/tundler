package main

import (
	"log"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	"github.com/laurentpellegrino/tundler/internal/geo"
)

// Fleet-wide soft region spread.
//
// Problem: pickLocation is uniform-random per pod with zero
// coordination, so a 70-pod fleet clusters on popular countries by
// chance. Coordinating for real (leases, peer scraping) is off the
// table: the tunnel ServiceAccount has no RBAC beyond `get nodes`, and
// several provider clients rewrite resolv.conf so cross-pod DNS dies
// mid-life.
//
// Solution: make the spread DETERMINISTIC instead of coordinated. The
// deployment renderer already has global fleet knowledge, so it gives
// every StatefulSet two static ints — TUNDLER_FLEET_SLOT_BASE (the
// first fleet-global slot of this provider's block) and
// TUNDLER_FLEET_SLOTS (fleet total). Every pod computes the SAME
// epoch-seeded shuffled country ring (geo.PreferredOrder); the
// provider's block start (BASE/SLOTS of the way around the ring) picks
// where this provider begins, and the provider's pods then take
// CONSECUTIVE countries from the ring-ordered list of countries the
// provider actually offers: ordinal 0 the first offered country at or
// after the block start, ordinal 1 the next, and so on. Siblings never
// share a country unless the provider offers fewer countries than it
// has pods — the "no other choice" case.
//
// Why by ordinal over the OFFERED list and not by fleet slot over the
// whole ring: siblings hold adjacent fleet slots, so when each walked
// the full ring from its own slot the walk from neighbouring starts
// resolved to the same next offered country. Observed in production on
// 2026-10-19: the 7 OVPN pods (17 countries on offer, 146 in the ring)
// would have collapsed onto 2 countries — worse than uniform random.
//
// This is a PREFERENCE, never a guarantee: any miss (provider has no
// mappable catalog — Windscribe cities, "auto" — or every preferred
// country is excluded/unavailable) falls back to the legacy uniform
// random pick. Disabled entirely when the env vars are absent.
const (
	envFleetSlotBase = "TUNDLER_FLEET_SLOT_BASE"
	envFleetSlots    = "TUNDLER_FLEET_SLOTS"
)

type locationPreference struct {
	base    int // first fleet-global slot of this provider's block
	ordinal int // this pod's StatefulSet ordinal (rank within the block)
	slot    int // base + ordinal: this pod's fleet-global slot, in [0, slots)
	slots   int // fleet-wide pod total

	// steps counts completed rotations: each rotation advances the walk
	// one position along the country ring so a pod explores different
	// countries over its lifetime instead of pinning one forever.
	// Watchdog reconnects do NOT advance — a drop is not a rotation,
	// and re-picking the same position keeps the fleet layout stable.
	steps atomic.Int64

	now func() time.Time // injectable for tests
}

// newLocationPreferenceFromEnv builds the preference from the
// renderer-provided env, or returns nil (feature off → pure legacy
// random behavior) when the vars are absent or inconsistent.
func newLocationPreferenceFromEnv() *locationPreference {
	baseStr := strings.TrimSpace(os.Getenv(envFleetSlotBase))
	slotsStr := strings.TrimSpace(os.Getenv(envFleetSlots))
	if baseStr == "" || slotsStr == "" {
		return nil
	}
	base, errB := strconv.Atoi(baseStr)
	total, errT := strconv.Atoi(slotsStr)
	if errB != nil || errT != nil || total <= 0 {
		log.Printf("tundler-tunnel: invalid %s=%q / %s=%q — region preference disabled",
			envFleetSlotBase, baseStr, envFleetSlots, slotsStr)
		return nil
	}
	ordinal := accounts.PodOrdinal()
	slot := base + ordinal
	if slot < 0 || slot >= total {
		log.Printf("tundler-tunnel: fleet slot %d (base %d + ordinal %d) outside [0,%d) — region preference disabled",
			slot, base, ordinal, total)
		return nil
	}
	return &locationPreference{base: base, ordinal: ordinal, slot: slot, slots: total, now: time.Now}
}

// pick returns (location, countryAlpha2, true) when a preferred country
// is available, or ok=false meaning "caller falls back to pickLocation"
// — the always-fall-back contract.
func (p *locationPreference) pick(locations, excluded []string) (string, string, bool) {
	// Excluded filtering happens BEFORE country grouping, so a country
	// whose every location is excluded is invisible to the walk — never
	// fought over, never wastefully preferred.
	excludeSet := make(map[string]struct{}, len(excluded))
	for _, e := range excluded {
		if e = strings.TrimSpace(e); e != "" {
			excludeSet[e] = struct{}{}
		}
	}
	byCountry := make(map[string][]string)
	for _, loc := range locations {
		if _, blocked := excludeSet[loc]; blocked {
			continue
		}
		if cc, ok := geo.GuessAlpha2(loc); ok {
			byCountry[cc] = append(byCountry[cc], loc)
		}
	}
	if len(byCountry) == 0 {
		return "", "", false
	}

	order := geo.PreferredOrder(geo.Epoch(p.now()))
	// The provider's block starts base/slots of the way around the
	// ring, so different providers begin at different places of the
	// same permutation.
	start := p.base * len(order) / p.slots
	// Offered countries in ring order from the block start. Siblings
	// then index this list by ordinal (+ completed rotations), which
	// hands each of them a distinct country for as long as the catalog
	// has one to spare.
	offered := make([]string, 0, len(byCountry))
	for i := 0; i < len(order); i++ {
		cc := order[(start+i)%len(order)]
		if len(byCountry[cc]) > 0 {
			offered = append(offered, cc)
		}
	}
	if len(offered) == 0 {
		return "", "", false
	}
	cc := offered[(p.ordinal+int(p.steps.Load()))%len(offered)]
	candidates := byCountry[cc]
	return candidates[rand.IntN(len(candidates))], cc, true
}

// advance moves the walk one country forward. Called by the rotation
// path only (see steps field doc).
func (p *locationPreference) advance() {
	p.steps.Add(1)
}
