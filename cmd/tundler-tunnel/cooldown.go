package main

import (
	"log"
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
// A /rotate carrying `reason=blocked` now puts the current location
// AND its country on a cool-down list. Picks skip cooled entries for
// TUNDLER_BLOCKED_COOLDOWN (default 6h) — long enough to outlive the
// crawler's own pause and the next few rotations, short enough that a
// provider with a tiny catalog gets its countries back the same day.
// Siblings keep their own lists: no coordination, same as the region
// preference. When everything on offer is cooled the cool-down is
// ignored rather than leaving the pod without a location.
const (
	envBlockedCooldown     = "TUNDLER_BLOCKED_COOLDOWN"
	defaultBlockedCooldown = 6 * time.Hour
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
