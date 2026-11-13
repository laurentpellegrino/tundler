package main

import (
	"strings"
	"sync"
	"time"
)

// Advised locations.
//
// A pod only knows the exits it used itself (see cooldown.go). The
// caller of POST /rotate may see every pod's exits, and so know which
// locations would hand this pod a prefix another pod used within the
// upstream's quota window. It can name them in the request body
// ({"avoid_locations": ["...", "..."]}), in the same vocabulary /status
// reports as current_location. The pick for that rotation skips them
// the way it skips cooling and spent locations, and ignores them when
// nothing else is left.
//
// The list is advice for one rotation, not memory. It is dropped as
// soon as a tunnel comes up, so a scheduled relocation or a later
// reconnect never picks by an old list. When the rotation fails it
// stays for the watchdog reconnect that follows, for at most
// advisedTTL. A request without a list drops the previous one.
const (
	maxAdvisedLocations = 1024
	maxAdvisedNameBytes = 128
	advisedTTL          = 10 * time.Minute
)

type advisedLocations struct {
	mu    sync.Mutex
	now   func() time.Time
	until time.Time
	names map[string]struct{}
}

func newAdvisedLocations() *advisedLocations {
	return &advisedLocations{now: time.Now, names: map[string]struct{}{}}
}

// advised is the list named by the last rotation request, set once in
// main() like blocked and exits. nil = none.
var advised *advisedLocations

// set replaces the list and reports how many names it kept: blank and
// oversize names are dropped, names past maxAdvisedLocations ignored.
// An empty list clears it.
func (a *advisedLocations) set(names []string) int {
	if a == nil {
		return 0
	}
	kept := make(map[string]struct{}, len(names))
	for _, name := range names {
		if len(kept) >= maxAdvisedLocations {
			break
		}
		name = strings.TrimSpace(name)
		if name == "" || len(name) > maxAdvisedNameBytes {
			continue
		}
		kept[name] = struct{}{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.names = kept
	a.until = a.now().Add(advisedTTL)
	return len(kept)
}

// clear drops the list.
func (a *advisedLocations) clear() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.names = map[string]struct{}{}
}

// liveLocked returns the names while the list is in force.
func (a *advisedLocations) liveLocked() map[string]struct{} {
	if len(a.names) > 0 && !a.now().Before(a.until) {
		a.names = map[string]struct{}{}
	}
	return a.names
}

// skip reports whether the caller named location.
func (a *advisedLocations) skip(location string) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.liveLocked()[strings.TrimSpace(location)]
	return ok
}

// list returns the names in force.
func (a *advisedLocations) list() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	names := a.liveLocked()
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	return out
}

// count is len(list()), for /status.
func (a *advisedLocations) count() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.liveLocked())
}
