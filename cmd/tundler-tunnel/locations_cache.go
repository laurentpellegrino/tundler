package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
)

const (
	envLocationsCacheTTLSec = "LOCATIONS_CACHE_TTL_SECONDS"
	// Region catalogs are static for hours, so a long TTL is safe. 30 min
	// still picks up a provider adding/removing regions within a pod's
	// lifetime while forking the daemon CLI at most twice an hour.
	defaultLocationsCacheTTLSec = 1800
)

func locationsCacheTTL() time.Duration {
	return time.Duration(getEnvInt(envLocationsCacheTTLSec, defaultLocationsCacheTTLSec)) * time.Second
}

// cachedLocationsProvider decorates ANY VPNProvider so Locations() is
// memoized for a TTL. It exists for two reasons, both aimed at the
// daemon-CLI-fork cost and the shared-account throttle:
//
//   - fewer CLI forks: for the CLI-backed providers (expressvpn / pia /
//     nordvpn) `get regions` is forked once per TTL instead of on every
//     connect / rotate / watchdog attempt;
//   - resilience to a wedged daemon: if a refresh returns empty/nil — the
//     expressvpnctl-times-out-returns-nil pathology — we keep serving the
//     LAST-GOOD catalog instead of reporting "0 available", which is what
//     used to tip a throttled tunnel into a tight reconnect spiral.
//
// Empty results are never cached as "good": until the underlying returns a
// non-empty list we pass through on every call, so cold-start catalog
// loading (e.g. expressvpn's [smart] placeholder window) still works. The
// file/static-list providers are unaffected — caching a cheap read is
// harmless. Every other VPNProvider method forwards to the embedded
// provider unchanged.
type cachedLocationsProvider struct {
	provider.VPNProvider
	ttl time.Duration
	now func() time.Time // injectable for tests

	mu        sync.Mutex
	cached    []string
	fetchedAt time.Time
}

func newCachedLocationsProvider(p provider.VPNProvider, ttl time.Duration) *cachedLocationsProvider {
	return &cachedLocationsProvider{VPNProvider: p, ttl: ttl, now: time.Now}
}

func (c *cachedLocationsProvider) Locations(ctx context.Context) []string {
	c.mu.Lock()
	cached := c.cached
	fresh := len(cached) > 0 && c.now().Sub(c.fetchedAt) < c.ttl
	c.mu.Unlock()
	if fresh {
		return cached
	}

	got := c.VPNProvider.Locations(ctx)
	if len(got) == 0 {
		// Refresh failed (wedged CLI / cold start). Serve the last-good
		// catalog if we have one rather than propagating "0 available".
		if len(cached) > 0 {
			log.Printf("tundler-tunnel: Locations() refresh returned empty; serving %d cached region(s)", len(cached))
			return cached
		}
		return got
	}

	c.mu.Lock()
	c.cached = got
	c.fetchedAt = c.now()
	c.mu.Unlock()
	return got
}
