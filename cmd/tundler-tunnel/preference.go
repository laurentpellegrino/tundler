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
// TUNDLER_FLEET_SLOTS (fleet total) — and each pod derives its own
// fleet-unique slot as BASE + podOrdinal. Every pod then walks the SAME
// epoch-seeded shuffled country ring (geo.PreferredOrder), starting at
// its own evenly-spaced offset, and prefers the first country its
// provider actually offers. Pods can't collide unless their walks wrap
// onto each other — which is exactly the "no other choice" case.
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
	slot  int // this pod's fleet-global slot, in [0, slots)
	slots int // fleet-wide pod total

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
	slot := base + accounts.PodOrdinal()
	if slot < 0 || slot >= total {
		log.Printf("tundler-tunnel: fleet slot %d (base %d + ordinal %d) outside [0,%d) — region preference disabled",
			slot, base, accounts.PodOrdinal(), total)
		return nil
	}
	return &locationPreference{slot: slot, slots: total, now: time.Now}
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
	// Evenly-spaced start offsets: slot i of N starts i/N of the way
	// around the ring, so pods spread across the whole permutation
	// instead of clustering at its head.
	start := p.slot * len(order) / p.slots
	pos := (start + int(p.steps.Load())) % len(order)
	for i := 0; i < len(order); i++ {
		cc := order[(pos+i)%len(order)]
		if candidates := byCountry[cc]; len(candidates) > 0 {
			return candidates[rand.IntN(len(candidates))], cc, true
		}
	}
	return "", "", false
}

// advance moves the walk one country forward. Called by the rotation
// path only (see steps field doc).
func (p *locationPreference) advance() {
	p.steps.Add(1)
}
