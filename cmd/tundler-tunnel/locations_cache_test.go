package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

// scriptedLocations is a VPNProvider whose Locations() return value is
// driven by a per-call script, and which counts how many times the
// underlying (un-cached) Locations was actually invoked. It embeds
// *fakeProvider for every other method.
type scriptedLocations struct {
	*fakeProvider
	mu     sync.Mutex
	calls  int
	script func(call int) []string
}

func (s *scriptedLocations) Locations(_ context.Context) []string {
	s.mu.Lock()
	s.calls++
	n, fn := s.calls, s.script
	s.mu.Unlock()
	return fn(n)
}

func (s *scriptedLocations) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func newScripted(script func(call int) []string) *scriptedLocations {
	return &scriptedLocations{fakeProvider: &fakeProvider{}, script: script}
}

func TestLocationsCache_MemoizesWithinTTL(t *testing.T) {
	under := newScripted(func(int) []string { return []string{"USA", "Canada"} })
	now := time.Unix(0, 0)
	c := newCachedLocationsProvider(under, time.Minute)
	c.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		got := c.Locations(context.Background())
		if len(got) != 2 {
			t.Fatalf("call %d: got %v, want 2 regions", i, got)
		}
	}
	if under.callCount() != 1 {
		t.Errorf("underlying Locations forked %d times within TTL, want 1", under.callCount())
	}
}

func TestLocationsCache_RefreshesAfterTTL(t *testing.T) {
	under := newScripted(func(int) []string { return []string{"USA"} })
	now := time.Unix(0, 0)
	c := newCachedLocationsProvider(under, time.Minute)
	c.now = func() time.Time { return now }

	c.Locations(context.Background()) // populate (fork 1)
	now = now.Add(2 * time.Minute)    // expire
	c.Locations(context.Background()) // refork (fork 2)

	if under.callCount() != 2 {
		t.Errorf("underlying forked %d times across a TTL boundary, want 2", under.callCount())
	}
}

// The key resilience property: once a good catalog is cached, a refresh
// that returns empty (wedged daemon CLI) must NOT blank it out — we keep
// serving the last-good list rather than reporting "0 available".
func TestLocationsCache_ServesLastGoodOnEmptyRefresh(t *testing.T) {
	under := newScripted(func(call int) []string {
		if call == 1 {
			return []string{"USA", "Canada"} // good first fetch
		}
		return nil // every subsequent fetch: wedged CLI
	})
	now := time.Unix(0, 0)
	c := newCachedLocationsProvider(under, time.Minute)
	c.now = func() time.Time { return now }

	first := c.Locations(context.Background()) // fork 1 → cache [USA, Canada]
	if len(first) != 2 {
		t.Fatalf("first fetch got %v, want 2", first)
	}
	now = now.Add(2 * time.Minute) // force a refresh that will return nil

	got := c.Locations(context.Background())
	if len(got) != 2 {
		t.Fatalf("after wedged refresh got %v, want last-good 2 regions", got)
	}
}

// Cold start: while the underlying returns empty (catalog still loading) we
// must pass through every call, never caching the empty as "good".
func TestLocationsCache_ColdStartPassesThroughEmpty(t *testing.T) {
	under := newScripted(func(call int) []string {
		if call < 3 {
			return nil // still loading
		}
		return []string{"USA"} // catalog ready
	})
	now := time.Unix(0, 0)
	c := newCachedLocationsProvider(under, time.Minute)
	c.now = func() time.Time { return now }

	if got := c.Locations(context.Background()); got != nil {
		t.Fatalf("call 1 got %v, want nil (still loading)", got)
	}
	if got := c.Locations(context.Background()); got != nil {
		t.Fatalf("call 2 got %v, want nil (still loading)", got)
	}
	if got := c.Locations(context.Background()); len(got) != 1 {
		t.Fatalf("call 3 got %v, want [USA]", got)
	}
	// Call 3 cached the good catalog; a 4th call within TTL is a cache hit
	// and must NOT fork again — so the underlying stays at 3 forks.
	c.Locations(context.Background())
	if under.callCount() != 3 {
		t.Errorf("underlying forked %d times, want 3 (calls 1-3, then a cache hit)", under.callCount())
	}
}
