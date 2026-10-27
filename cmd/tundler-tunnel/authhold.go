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
// The hold is process-wide: after an auth failure every connect path
// (boot, rotation, watchdog) waits it out instead of its usual short
// backoff. It starts at TUNDLER_AUTH_FAILURE_BACKOFF_SECONDS (default
// 1 h), doubles on each consecutive auth failure up to 24 h, and clears
// on the first successful connect. The pod stays up and NotReady
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
)

// errAuthFailed wraps a connect the provider rejected for credentials.
var errAuthFailed = errors.New("provider rejected the account credentials")

type authHold struct {
	mu      sync.Mutex
	base    time.Duration
	strikes int       // consecutive auth failures
	until   time.Time // zero when no hold is active
	now     func() time.Time
}

// hold is the process-wide auth hold, set in main() before any connect.
var hold = newAuthHold(time.Duration(defaultAuthFailureBackoff) * time.Second)

func newAuthHold(base time.Duration) *authHold {
	if base <= 0 {
		base = time.Duration(defaultAuthFailureBackoff) * time.Second
	}
	return &authHold{base: base, now: time.Now}
}

func newAuthHoldFromEnv() *authHold {
	return newAuthHold(time.Duration(getEnvInt(envAuthFailureBackoff, defaultAuthFailureBackoff)) * time.Second)
}

// strike records an auth failure and returns the hold it imposes.
func (h *authHold) strike() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	wait := h.base
	for i := 0; i < h.strikes && wait < maxAuthFailureBackoff; i++ {
		wait *= 2
	}
	if wait > maxAuthFailureBackoff {
		wait = maxAuthFailureBackoff
	}
	h.strikes++
	h.until = h.now().Add(wait)
	return wait
}

// clear ends the hold: the account authenticated again.
func (h *authHold) clear() {
	h.mu.Lock()
	h.strikes = 0
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

// noteAuthFailure is the one place every connect path reports a
// credential rejection: counts it on /status, starts the hold, logs.
func noteAuthFailure(state *StateTracker, providerName, location string) time.Duration {
	wait := hold.strike()
	state.RecordAuthFailure("provider=" + providerName + " rejected the credentials on connect (location=" + location + ")")
	state.SetAuthHold(hold.deadline())
	log.Printf("tundler-tunnel: provider=%s rejected the account credentials (location=%s); holding every connect for %s (strike %d) — no retry elsewhere, no re-login",
		providerName, location, wait.Round(time.Second), hold.strikesCount())
	return wait
}

func (h *authHold) strikesCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.strikes
}
