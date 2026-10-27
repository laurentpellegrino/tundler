package main

import (
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"sync"
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
// Where the two ints come from: preferably the fleet topology file
// (vpn-providers.yaml mounted from the renderer's ConfigMap, see
// fleet.go) which every pod re-reads at each pick, so a topology edit
// lands at the next rotation without a pod roll; otherwise the static
// env vars the renderer used to inject.
//
// This is a PREFERENCE, never a guarantee: any miss (provider has no
// mappable catalog — Windscribe cities, "auto" — or every preferred
// country is excluded/unavailable) falls back to the legacy uniform
// random pick. Disabled entirely when neither source is available.
const (
	envFleetSlotBase = "TUNDLER_FLEET_SLOT_BASE"
	envFleetSlots    = "TUNDLER_FLEET_SLOTS"
	envFleetReplicas = "TUNDLER_FLEET_REPLICAS"
	envCountryDwell  = "TUNDLER_COUNTRY_DWELL"

	defaultCountryDwell = 4
)

type locationPreference struct {
	// mu guards the layout fields (base, slot, slots, replicas), which
	// refresh() may move when the topology file changes.
	mu      sync.Mutex
	base    int // first fleet-global slot of this provider's block
	ordinal int // this pod's StatefulSet ordinal (rank within the block)
	slot    int // base + ordinal: this pod's fleet-global slot, in [0, slots)
	slots   int // fleet-wide pod total
	// replicas is this provider's pod count: the stride of the walk
	// over the offered list (1 when the layout did not provide it);
	// width is the raw count the layout stated, kept to detect change.
	replicas int
	width    int
	// layoutPath is the topology file re-read at every pick ("" when
	// the layout came from env and is static); provider is this pod's
	// entry in it. onSlot, when set, is told about a moved slot.
	layoutPath string
	provider   string
	onSlot     func(slot int)
	// cooldown is the blocked-exit memory consulted by pick (nil = none).
	cooldown *locationCooldown
	// dwell counts rotations spent at the current position; dwellCap is
	// how many a pod spends in one country before moving on regardless
	// of pool evidence (0 = advance on every rotation).
	dwell    atomic.Int64
	dwellCap int
	// avoid is the location just rotated away from: a re-pick in the
	// same country prefers another location when the country has one.
	avoid atomic.Value // string

	// steps counts completed rotations: each rotation advances the walk
	// one position along the country ring so a pod explores different
	// countries over its lifetime instead of pinning one forever.
	// Watchdog reconnects do NOT advance — a drop is not a rotation,
	// and re-picking the same position keeps the fleet layout stable.
	steps atomic.Int64

	now func() time.Time // injectable for tests
}

// newLocationPreference builds the preference for provider from the
// fleet topology file when it is mounted and lists the provider, else
// from the renderer-provided env, or returns nil (feature off → pure
// legacy random behavior) when neither source is usable.
func newLocationPreference(provider string) *locationPreference {
	path := fleetLayoutPath()
	layout, err := readFleetLayout(path, provider)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("tundler-tunnel: fleet layout %s unusable (%v) — falling back to env", path, err)
		}
		return newLocationPreferenceFromEnv()
	}
	p := newLocationPreferenceFrom(layout, accounts.PodOrdinal())
	if p == nil {
		return nil
	}
	p.layoutPath = path
	p.provider = provider
	log.Printf("tundler-tunnel: fleet layout from %s: slot %d/%d, stride %d", path, p.slot, p.slots, p.replicas)
	return p
}

// newLocationPreferenceFromEnv builds the preference from the
// renderer-provided env, or returns nil when the vars are absent or
// inconsistent.
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
	replicas := 0
	if raw := strings.TrimSpace(os.Getenv(envFleetReplicas)); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			log.Printf("tundler-tunnel: invalid %s=%q — walking the ring with stride 1", envFleetReplicas, raw)
		} else {
			replicas = n
		}
	}
	return newLocationPreferenceFrom(fleetLayout{base: base, slots: total, replicas: replicas}, accounts.PodOrdinal())
}

// newLocationPreferenceFrom places pod ordinal in layout, or returns nil
// when the pod falls outside the fleet range.
func newLocationPreferenceFrom(layout fleetLayout, ordinal int) *locationPreference {
	slot := layout.base + ordinal
	if layout.slots <= 0 || slot < 0 || slot >= layout.slots {
		log.Printf("tundler-tunnel: fleet slot %d (base %d + ordinal %d) outside [0,%d) — region preference disabled",
			slot, layout.base, ordinal, layout.slots)
		return nil
	}
	return &locationPreference{base: layout.base, ordinal: ordinal, slot: slot, slots: layout.slots,
		replicas: stride(layout.replicas, ordinal), width: layout.replicas,
		dwellCap: getEnvInt(envCountryDwell, defaultCountryDwell), now: time.Now}
}

// stride is the walk stride for a provider of replicas pods: 1 when the
// count is unknown or stale (an ordinal at or past it means the layout
// predates a scale-up).
func stride(replicas, ordinal int) int {
	if replicas <= 0 || ordinal >= replicas {
		if replicas > 0 {
			log.Printf("tundler-tunnel: fleet replicas %d stale for ordinal %d — walking the ring with stride 1",
				replicas, ordinal)
		}
		return 1
	}
	return replicas
}

// refresh re-reads the topology file and moves the layout when it
// changed. A missing or unparsable file keeps the last good layout: the
// ConfigMap projection may be mid-update, and a stale preference beats
// none. Reports whether this pod still has a slot in the fleet.
func (p *locationPreference) refresh() bool {
	if p.layoutPath == "" {
		return true
	}
	layout, err := readFleetLayout(p.layoutPath, p.provider)
	if err != nil {
		slot, slots, _ := p.position()
		log.Printf("tundler-tunnel: fleet layout %s: %v — keeping slot %d/%d", p.layoutPath, err, slot, slots)
		return true
	}
	p.mu.Lock()
	changed := layout.base != p.base || layout.slots != p.slots || layout.replicas != p.width
	if !changed {
		p.mu.Unlock()
		return true
	}
	was := fmt.Sprintf("%d/%d stride %d", p.slot, p.slots, p.replicas)
	p.base, p.slots, p.width = layout.base, layout.slots, layout.replicas
	p.slot = layout.base + p.ordinal
	p.replicas = stride(layout.replicas, p.ordinal)
	slot, slots, replicas := p.slot, p.slots, p.replicas
	p.mu.Unlock()
	log.Printf("tundler-tunnel: fleet layout changed: slot %s → %d/%d stride %d", was, slot, slots, replicas)
	if p.onSlot != nil {
		p.onSlot(slot)
	}
	return slot >= 0 && slot < slots
}

// position reports this pod's current slot, the fleet total and the
// walk stride.
func (p *locationPreference) position() (slot, slots, replicas int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.slot, p.slots, p.replicas
}

// pick returns (location, countryAlpha2, true) when a preferred country
// is available, or ok=false meaning "caller falls back to pickLocation"
// — the always-fall-back contract.
func (p *locationPreference) pick(locations, excluded []string) (string, string, bool) {
	if !p.refresh() {
		return "", "", false // scaled out of the fleet: the pod is on its way out
	}
	p.mu.Lock()
	base, slots, replicas := p.base, p.slots, p.replicas
	p.mu.Unlock()
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
	start := base * len(order) / slots
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
	cc, candidates := p.choose(offered, byCountry, replicas)
	if avoid, _ := p.avoid.Load().(string); avoid != "" && len(candidates) > 1 {
		fresh := make([]string, 0, len(candidates))
		for _, loc := range candidates {
			if loc != avoid {
				fresh = append(fresh, loc)
			}
		}
		if len(fresh) > 0 {
			candidates = fresh
		}
	}
	return candidates[rand.IntN(len(candidates))], cc, true
}

// choose walks this pod's residue class of the offered list from its
// current position until it finds a country that is not cooling (and
// still has a location that is not cooling). Falls back to walking the
// whole list, then to ignoring the cool-down entirely.
func (p *locationPreference) choose(offered []string, byCountry map[string][]string, stride int) (string, []string) {
	if stride < 1 {
		stride = 1
	}
	span := len(offered)
	if span >= stride {
		span -= span % stride
	} else {
		stride = 1 // fewer countries than pods: sharing is unavoidable
	}
	steps := int(p.steps.Load())
	at := func(k int) int { return (p.ordinal + (steps+k)*stride) % span }
	first := at(0)
	for k := 0; k*stride < span; k++ {
		cc := offered[at(k)]
		if candidates := p.warm(cc, byCountry[cc]); len(candidates) > 0 {
			return cc, candidates
		}
	}
	for i := 1; i < len(offered); i++ {
		cc := offered[(first+i)%len(offered)]
		if candidates := p.warm(cc, byCountry[cc]); len(candidates) > 0 {
			return cc, candidates
		}
	}
	cc := offered[first]
	return cc, byCountry[cc]
}

// warm returns the locations of cc that are not cooling, or nil when
// the country itself is cooling.
func (p *locationPreference) warm(cc string, locations []string) []string {
	if p.cooldown == nil {
		return locations
	}
	if p.cooldown.cooledCountry(cc) {
		return nil
	}
	out := make([]string, 0, len(locations))
	for _, loc := range locations {
		if !p.cooldown.cooledLocation(loc) {
			out = append(out, loc)
		}
	}
	return out
}

// advance moves the walk one position forward and resets the dwell.
func (p *locationPreference) advance() {
	p.steps.Add(1)
	p.dwell.Store(0)
}

// rotated is called once per rotation (never for watchdog reconnects):
// it counts the dwell and advances the walk once the cap is reached.
// Reports whether the walk moved. leaving is the location being rotated
// away from, avoided by the re-pick when the country offers another.
func (p *locationPreference) rotated(leaving string) bool {
	p.avoid.Store(leaving)
	if p.dwellCap <= 0 || p.dwell.Add(1) >= int64(p.dwellCap) {
		p.advance()
		return true
	}
	return false
}

// leave moves the walk on because the current country's pool is
// exhausted (a rotation repeated an exit this pod already used).
func (p *locationPreference) leave() {
	p.advance()
}

// settled clears the avoided location once a tunnel is up.
func (p *locationPreference) settled() {
	p.avoid.Store("")
}
