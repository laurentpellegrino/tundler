package main

import (
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// Blocked-exit memory.
//
// The crawler slot pinned to this pod knows when an exit is burned: it
// drives its rate down to the AIMD floor, still gets 429s, and only
// then POSTs /rotate. Until now the pod learnt nothing from that call
// and could re-pick the same location (random fallback, small
// catalogs, watchdog reconnects) or the same country minutes later.
//
// A rotation that lands on a burnt prefix (see exitMemory) puts the
// location AND its country on a cool-down list. Picks skip cooled
// entries for TUNDLER_BLOCKED_COOLDOWN (default 1h): on the ExpressVPN
// fleet a throttled /24 served at full rate again after a 30-40 min
// gap, while shorter gaps were still throttled, so an hour outlives
// the quota window without hiding a pod's whole residue class behind
// cool-downs (each class holds ~13 countries and a small country is
// left after one exit; at 6h the class ran dry and the walk fell back
// to the whole list, colliding with siblings). Siblings keep their own
// lists: no coordination, same as the region preference. When
// everything on offer is cooled the cool-down is ignored rather than
// leaving the pod without a location.
const (
	envBlockedCooldown     = "TUNDLER_BLOCKED_COOLDOWN"
	defaultBlockedCooldown = time.Hour
)

type locationCooldown struct {
	mu        sync.Mutex
	ttl       time.Duration
	now       func() time.Time
	locations map[string]time.Time // location → expiry
	countries map[string]time.Time // alpha-2 → expiry
}

func newLocationCooldown(ttl time.Duration) *locationCooldown {
	return &locationCooldown{
		ttl:       ttl,
		now:       time.Now,
		locations: map[string]time.Time{},
		countries: map[string]time.Time{},
	}
}

// newLocationCooldownFromEnv reads TUNDLER_BLOCKED_COOLDOWN ("0"
// disables the memory: marks become no-ops). Invalid values fall back
// to the default and are logged, never fatal.
func newLocationCooldownFromEnv() *locationCooldown {
	ttl := defaultBlockedCooldown
	if raw := strings.TrimSpace(os.Getenv(envBlockedCooldown)); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed < 0 {
			log.Printf("tundler-tunnel: invalid %s=%q — using %s", envBlockedCooldown, raw, ttl)
		} else {
			ttl = parsed
		}
	}
	return newLocationCooldown(ttl)
}

// mark cools location and country (either may be "") until now+ttl.
func (c *locationCooldown) mark(location, country string) {
	if c == nil || c.ttl <= 0 {
		return
	}
	until := c.now().Add(c.ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if location = strings.TrimSpace(location); location != "" {
		c.locations[location] = until
	}
	if country = strings.TrimSpace(country); country != "" {
		c.countries[country] = until
	}
}

// cooledLocation reports whether location is still cooling.
func (c *locationCooldown) cooledLocation(location string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	_, ok := c.locations[location]
	return ok
}

// cooledCountry reports whether the alpha-2 country is still cooling.
func (c *locationCooldown) cooledCountry(country string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	_, ok := c.countries[country]
	return ok
}

// cooledLocations lists every location still cooling — appended to the
// excluded set by the legacy random pick, which has no country notion.
func (c *locationCooldown) cooledLocations() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	out := make([]string, 0, len(c.locations))
	for loc := range c.locations {
		out = append(out, loc)
	}
	return out
}

// counts returns (locations, countries) still cooling, for /status.
func (c *locationCooldown) counts() (int, int) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	return len(c.locations), len(c.countries)
}

func (c *locationCooldown) purgeLocked() {
	now := c.now()
	for k, until := range c.locations {
		if !until.After(now) {
			delete(c.locations, k)
		}
	}
	for k, until := range c.countries {
		if !until.After(now) {
			delete(c.countries, k)
		}
	}
}

// Exit memory.
//
// The upstream the crawler hits meters by prefix, not by address: on
// 2026-10-20 the first ExpressVPN exit in a /24 crawled at full rate
// for a median 14 min, every later exit from the same /24 was back at
// the 429 floor within a median 2 min (199 rotations, 38 prefixes).
// So a rotation that lands in a prefix this pod already used within
// TUNDLER_EXIT_MEMORY (default 1h, about twice the observed refill
// gap) buys nothing: that repeat — not the crawler's 429s on a single
// throttled address — is the signal that cools the location and
// country and moves the walk on. Keys are the /24 of an IPv4 exit and
// the /48 of an IPv6 one.
const (
	envExitMemory     = "TUNDLER_EXIT_MEMORY"
	defaultExitMemory = time.Hour
)

type exitMemory struct {
	mu   sync.Mutex
	ttl  time.Duration
	now  func() time.Time
	seen map[string]time.Time // exit prefix → last seen
}

// exitKey reduces an exit address to the prefix the upstream meters:
// /24 for IPv4, /48 for IPv6. Anything unparseable is kept verbatim so
// a provider CLI reporting something odd still gets exact-match
// memory.
func exitKey(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return strings.TrimSpace(ip)
	}
	bits := 48
	if addr.Unmap().Is4() {
		addr = addr.Unmap()
		bits = 24
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
}

func newExitMemory(ttl time.Duration) *exitMemory {
	return &exitMemory{ttl: ttl, now: time.Now, seen: map[string]time.Time{}}
}

func newExitMemoryFromEnv() *exitMemory {
	ttl := defaultExitMemory
	if raw := strings.TrimSpace(os.Getenv(envExitMemory)); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed < 0 {
			log.Printf("tundler-tunnel: invalid %s=%q — using %s", envExitMemory, raw, ttl)
		} else {
			ttl = parsed
		}
	}
	return newExitMemory(ttl)
}

// remember records ip's prefix as used now and reports whether this
// pod had already used that prefix within ttl. "" is never a repeat.
// A ttl of 0 disables the memory (never a repeat).
func (m *exitMemory) remember(ip string) bool {
	if m == nil || m.ttl <= 0 || strings.TrimSpace(ip) == "" {
		return false
	}
	key := exitKey(ip)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, at := range m.seen {
		if now.Sub(at) >= m.ttl {
			delete(m.seen, k)
		}
	}
	_, repeat := m.seen[key]
	m.seen[key] = now
	return repeat
}

// size reports how many distinct exit prefixes are remembered, for
// /status.
func (m *exitMemory) size() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen)
}
