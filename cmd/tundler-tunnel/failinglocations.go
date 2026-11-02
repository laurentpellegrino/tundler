package main

// Failing-location memory.
//
// Static EXCLUDED_LOCATIONS lists are a blunt tool: a location excluded
// once stays excluded until someone edits the list, and its exits are
// never seen again. Most location problems are temporary, so the pod
// learns them instead and forgets them on its own.
//
// A location is held (skipped by every pick) when:
//
//   - the provider rejects the credentials there (Status.AuthFailed).
//     The account-wide auth hold still applies; this only makes sure the
//     next connect after the hold goes somewhere else. On 2026-10-29 and
//     2026-11-02 the same OpenVPN server rejected the device credentials
//     of two different pods while every other server accepted them.
//   - it fails to connect (or connects without changing the egress IP)
//     a second time, with the pod connecting fine elsewhere since the
//     first failure there. A single failure is often the pod or the
//     network, not the location, and failures with no success anywhere
//     in between (an outage, a throttled account) hold nothing.
//
// The hold starts at TUNDLER_FAILING_LOCATION_HOLD (default 24h) and
// doubles each time the location fails again after its hold ended, up
// to 7 days, so a location that keeps failing is still retried about
// once a week and never dropped for good. The first successful connect
// there forgets it. When every location on offer is held the holds are
// ignored rather than leaving the pod without a location.
//
// The memory is per pod and in process: siblings learn on their own and
// a restart forgets it, which costs at most one more failure per pod.

import (
	"log"
	"strings"
	"sync"
	"time"
)

const (
	envFailingLocationHold     = "TUNDLER_FAILING_LOCATION_HOLD"
	defaultFailingLocationHold = 24 * time.Hour
	maxFailingLocationHold     = 7 * 24 * time.Hour
)

type failingEntry struct {
	strikes     int       // holds started so far
	lastFailure time.Time // last connect failure not yet turned into a hold
	until       time.Time // zero when not held
}

type failingLocations struct {
	mu          sync.Mutex
	base        time.Duration
	max         time.Duration
	now         func() time.Time
	lastSuccess time.Time // last successful connect, any location
	entries     map[string]*failingEntry
}

// failing is the process-wide failing-location memory, set in main()
// before any connect. A zero base disables it; it starts disabled so
// tests that fail connects on purpose do not hold locations for later
// tests.
var failing = newFailingLocations(0)

func newFailingLocations(base time.Duration) *failingLocations {
	return &failingLocations{
		base:    base,
		max:     maxFailingLocationHold,
		now:     time.Now,
		entries: map[string]*failingEntry{},
	}
}

func newFailingLocationsFromEnv() *failingLocations {
	return newFailingLocations(durationFromEnv(envFailingLocationHold, defaultFailingLocationHold))
}

// authFailed holds location at once. Returns the hold length (0 when
// the memory is disabled or location is empty).
func (f *failingLocations) authFailed(location string) time.Duration {
	if f == nil || f.base <= 0 {
		return 0
	}
	if location = strings.TrimSpace(location); location == "" {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startHoldLocked(f.entryLocked(location))
}

// connectFailed records a failed connect at location and holds it when
// it had already failed before the pod's last successful connect.
// Returns the hold length, 0 when the location is not (newly) held.
func (f *failingLocations) connectFailed(location string) time.Duration {
	if f == nil || f.base <= 0 {
		return 0
	}
	if location = strings.TrimSpace(location); location == "" {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.entryLocked(location)
	if e.lastFailure.IsZero() || !f.lastSuccess.After(e.lastFailure) {
		e.lastFailure = f.now()
		return 0
	}
	return f.startHoldLocked(e)
}

// succeeded forgets location (its next failure starts from scratch) and
// records that the pod can connect, which makes earlier failures
// elsewhere count.
func (f *failingLocations) succeeded(location string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastSuccess = f.now()
	delete(f.entries, strings.TrimSpace(location))
}

// held lists the locations whose hold has not ended.
func (f *failingLocations) held() []string {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	var out []string
	for loc, e := range f.entries {
		if e.until.After(now) {
			out = append(out, loc)
		}
	}
	return out
}

// heldCount is len(held()), for /status.
func (f *failingLocations) heldCount() int {
	return len(f.held())
}

func (f *failingLocations) entryLocked(location string) *failingEntry {
	e, ok := f.entries[location]
	if !ok {
		e = &failingEntry{}
		f.entries[location] = e
	}
	return e
}

// startHoldLocked starts the next hold: base, doubled per earlier hold,
// capped at max. A failure while a hold is still running (a pick that
// ignored the holds) extends nothing.
func (f *failingLocations) startHoldLocked(e *failingEntry) time.Duration {
	now := f.now()
	e.lastFailure = time.Time{}
	if e.until.After(now) {
		return 0
	}
	d := f.base
	for i := 0; i < e.strikes && d < f.max; i++ {
		d *= 2
	}
	if d > f.max {
		d = f.max
	}
	e.strikes++
	e.until = now.Add(d)
	return d
}

// noteFailingLocation logs a new hold; d == 0 means nothing was held.
func noteFailingLocation(providerName, location, why string, d time.Duration) {
	if d <= 0 {
		return
	}
	log.Printf("tundler-tunnel: provider=%s location=%s %s; skipping it for %s",
		providerName, location, why, d.Round(time.Minute))
}
