package main

// Auth-failure hold.
//
// A Connect that the provider rejects for the account's credentials
// (provider.Status.AuthFailed — OpenVPN AUTH_FAILED and the like) is
// not a location problem: retrying elsewhere cannot help, and with a
// provider that rate-limits logins every retry makes it worse. IPVanish
// is the motivating case: too many logins in a short window suspends
// the account for ~24 h and every further login extends the suspension,
// so the 2026-05 retry loop (a login every few minutes, forever) kept
// the account suspended indefinitely.
//
// A single rejection is not proof, though: most of them come from one
// server refusing a credential every other server accepts (IPVanish
// Italy, Albania, Andorra and Belize, Windscribe Latvia, FastVPN Ecuador
// in the week of 2026-11-02, each a one-off while the account worked
// everywhere else). So a rejection first holds that location
// (failinglocations.go) and the pod connects elsewhere; only
// TUNDLER_AUTH_FAILURES_BEFORE_HOLD rejections in a row (default 3, 1
// restores the old immediate hold) with no successful connect between
// them start the hold. The count survives the hold, so after it ends one
// more rejection holds again at the doubled length: a bad credential
// costs three logins, then one per hold.
//
// The hold is process-wide: once it starts every connect path (boot,
// rotation, watchdog) waits it out instead of its usual short backoff.
// It starts at TUNDLER_AUTH_FAILURE_BACKOFF_SECONDS (default 1 h),
// doubles on each further auth failure up to 24 h, and clears on the
// first successful connect. The pod stays up and NotReady
// meanwhile (/readyz 503, /livez 200) with auth_hold_until on /status,
// so a human sees it and fixing the credentials heals it in place.

import (
	"errors"
	"log"
	"sync"
	"time"
)

const (
	envAuthFailureBackoff     = "TUNDLER_AUTH_FAILURE_BACKOFF_SECONDS"
	defaultAuthFailureBackoff = 3600
	maxAuthFailureBackoff     = 24 * time.Hour
	envAuthFailuresBeforeHold = "TUNDLER_AUTH_FAILURES_BEFORE_HOLD"
	defaultAuthFailuresBefore = 3
)

// errAuthFailed wraps a connect the provider rejected for credentials.
var errAuthFailed = errors.New("provider rejected the account credentials")

type authHold struct {
	mu         sync.Mutex
	base       time.Duration
	max        time.Duration
	threshold  int       // rejections in a row that start the hold
	rejections int       // rejections since the last successful connect
	strikes    int       // holds started since the last successful connect
	until      time.Time // zero when no hold is active
	now        func() time.Time
}

// hold is the process-wide auth hold, set in main() before any connect.
var hold = newAuthHold(time.Duration(defaultAuthFailureBackoff) * time.Second)

func newAuthHold(base time.Duration) *authHold {
	if base <= 0 {
		base = time.Duration(defaultAuthFailureBackoff) * time.Second
	}
	return &authHold{base: base, max: maxAuthFailureBackoff, threshold: defaultAuthFailuresBefore, now: time.Now}
}

func newAuthHoldFromEnv() *authHold {
	h := newAuthHold(time.Duration(getEnvInt(envAuthFailureBackoff, defaultAuthFailureBackoff)) * time.Second)
	if n := getEnvInt(envAuthFailuresBeforeHold, defaultAuthFailuresBefore); n >= 1 {
		h.threshold = n
	}
	return h
}

// reject counts a credential rejection and reports whether it starts
// the hold (the threshold is reached) and how many rejections in a row
// there have been.
func (h *authHold) reject() (bool, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rejections++
	return h.rejections >= h.threshold, h.rejections
}

// strike records an auth failure and returns the hold it imposes.
func (h *authHold) strike() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	wait := h.base
	for i := 0; i < h.strikes && wait < h.max; i++ {
		wait *= 2
	}
	if wait > h.max {
		wait = h.max
	}
	h.strikes++
	h.until = h.now().Add(wait)
	return wait
}

// clear ends the hold: the account authenticated again.
func (h *authHold) clear() {
	h.mu.Lock()
	h.strikes = 0
	h.rejections = 0
	h.until = time.Time{}
	h.mu.Unlock()
}

// remaining is how long connects must still wait, 0 when free.
func (h *authHold) remaining() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.until.IsZero() {
		return 0
	}
	if r := h.until.Sub(h.now()); r > 0 {
		return r
	}
	return 0
}

// deadline is when the hold ends (zero when none).
func (h *authHold) deadline() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.until
}

// noteCredentialRejection is the one place every connect path reports a
// credential rejection. Below the threshold it holds that location and
// returns false: the caller moves on to another location. At the
// threshold it starts the auth hold (noteAuthFailure) and returns true:
// the caller stops like before.
func noteCredentialRejection(state *StateTracker, providerName, location string) bool {
	if starts, n := hold.reject(); !starts {
		log.Printf("tundler-tunnel: provider=%s rejected the credentials at location=%s (%d of %d in a row before holding the account); trying elsewhere",
			providerName, location, n, hold.threshold)
		noteFailingLocation(providerName, location, "rejected the credentials", failing.authFailed(location))
		return false
	}
	noteAuthFailure(state, providerName, location)
	return true
}

// noteAuthFailure starts the auth hold: counts it on /status (where the
// crawler's connection budget reads it), starts the hold, logs.
func noteAuthFailure(state *StateTracker, providerName, location string) time.Duration {
	wait := hold.strike()
	state.RecordAuthFailure("provider=" + providerName + " rejected the credentials on connect (location=" + location + ")")
	state.SetAuthHold(hold.deadline())
	log.Printf("tundler-tunnel: provider=%s rejected the account credentials (location=%s); holding every connect for %s (strike %d) — no retry elsewhere, no re-login",
		providerName, location, wait.Round(time.Second), hold.strikesCount())
	noteFailingLocation(providerName, location, "rejected the credentials", failing.authFailed(location))
	return wait
}

func (h *authHold) strikesCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.strikes
}
