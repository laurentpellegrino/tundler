package main

// Connect-throttle hold.
//
// NordVPN refuses a connect with "Too many connection attempts. Wait a
// while before trying again. Retrying now can make the waiting period
// longer." when an account's pods make about six connects within ten
// minutes. The watchdog used to retry every ~30 s, each retry one more
// attempt against the refusal. A connect the provider refuses this way
// (provider.Status.Throttled) now starts a process-wide hold like the
// auth-failure hold: every connect path waits it out and a /rotate
// leaves the current tunnel up. It starts at
// TUNDLER_THROTTLE_BACKOFF_SECONDS (default 300), doubles on each
// consecutive refusal up to 30 min and clears on the first successful
// connect. Unlike an auth failure it is not counted on /status
// auth_failures_total: the credentials are fine.

import (
	"errors"
	"log"
	"time"
)

const (
	envThrottleBackoff     = "TUNDLER_THROTTLE_BACKOFF_SECONDS"
	defaultThrottleBackoff = 300
	maxThrottleBackoff     = 30 * time.Minute
)

// errThrottled wraps a connect the provider refused for too many attempts.
var errThrottled = errors.New("provider refused the connect: too many connection attempts")

// throttle is the process-wide connect-throttle hold, set in main().
var throttle = newThrottleHold(time.Duration(defaultThrottleBackoff) * time.Second)

func newThrottleHold(base time.Duration) *authHold {
	if base <= 0 {
		base = time.Duration(defaultThrottleBackoff) * time.Second
	}
	return &authHold{base: base, max: maxThrottleBackoff, now: time.Now}
}

func newThrottleHoldFromEnv() *authHold {
	return newThrottleHold(time.Duration(getEnvInt(envThrottleBackoff, defaultThrottleBackoff)) * time.Second)
}

// noteThrottled is the one place every connect path reports a throttle
// refusal: starts the hold and logs.
func noteThrottled(providerName, location string) time.Duration {
	wait := throttle.strike()
	log.Printf("tundler-tunnel: provider=%s refused the connect for too many connection attempts (location=%s); holding every connect for %s (strike %d)",
		providerName, location, wait.Round(time.Second), throttle.strikesCount())
	return wait
}

// connectHoldRemaining is how long any connect must still wait: the
// longer of the auth-failure and the throttle holds.
func connectHoldRemaining() time.Duration {
	return max(hold.remaining(), throttle.remaining())
}
