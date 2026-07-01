package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
)

// reloginThrottleSec bounds how often this process re-logs-in after finding
// the daemon logged out mid-life, so a provider/account that keeps
// invalidating the session can't drive a login storm (the exact churn that
// trips shared-account detection).
const reloginThrottleSec = 60

// lastReloginUnix is the unix-seconds timestamp of the last re-login (one
// provider per process, so package state is fine).
var lastReloginUnix atomic.Int64

// ensureLoggedIn re-authenticates if the provider daemon has lost its
// session SINCE boot. The watchdog and rotation reconnect paths were built
// on the assumption that login is one-shot (the VPN client caches the
// session), so they reconnect WITHOUT re-logging-in. But a daemon can get
// logged out mid-life — observed 2026-06-12: expressvpnctl reports "Not
// logged in" hours after a successful boot login, and because nothing
// re-runs Login() the watchdog reconnect-loops forever, leaving the slot
// stuck at 0 rps until a manual pod restart. This closes that gap: only
// re-logins when the daemon actually reports logged-out, and throttled so a
// flapping session can't storm the account.
func ensureLoggedIn(ctx context.Context, prov provider.VPNProvider, providerName string) error {
	if prov.LoggedIn(ctx) {
		return nil
	}
	now := time.Now().Unix()
	last := lastReloginUnix.Load()
	if now-last < reloginThrottleSec {
		return fmt.Errorf("provider=%s daemon not logged in; re-login throttled (%ds)", providerName, reloginThrottleSec)
	}
	if !lastReloginUnix.CompareAndSwap(last, now) {
		return fmt.Errorf("provider=%s re-login already in progress", providerName)
	}
	log.Printf("tundler-tunnel: provider=%s daemon lost its session mid-life — re-running Login()", providerName)
	return prov.Login(ctx)
}

// connectTunnel picks a random allowed location (provider.Locations()
// minus `excluded`) and connects through it. On success, verifies the
// exit-IP contract (post-VPN egress IP differs from baselineEgressIP),
// records the tunnel-up details into state, and transitions to
// StateReady. On failure, returns an error; caller decides whether
// to retry or surrender.
//
// Used by the initial connect (from main) and the watchdog reconnect
// path (when an unexpected tunnel drop is detected). The rotation path
// uses connectWithRetry instead, to support the design-doc
// "failed-rotation handling" retry-with-different-location flow.
//
// State transitions:
//
//	(any) → StateConnecting → (Connect call + exit-IP verify) → StateReady (success)
//	                                                          → (return error) (failure; caller sets Failed)
func connectTunnel(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, baselineEgressIP string) error {
	state.Set(StateConnecting)
	if err := ensureLoggedIn(ctx, prov, providerName); err != nil {
		return err
	}
	available := prov.Locations(ctx)
	location, err := pickLocation(available, excluded)
	if err != nil {
		return fmt.Errorf("pick location for provider=%s (%d available, %d excluded): %w",
			providerName, len(available), len(excluded), err)
	}
	log.Printf("tundler-tunnel: provider=%s connecting to location=%s", providerName, location)
	status := prov.Connect(ctx, location)
	if !status.Connected {
		return fmt.Errorf("connect failed for provider=%s location=%s status=%+v",
			providerName, location, status)
	}
	observed, err := verifyExitIPDiffers(ctx, baselineEgressIP)
	if err != nil {
		// Tear the tunnel down so the pod doesn't sit in a half-up
		// state where /status reports Connected but traffic leaks.
		// Best-effort: ignore Disconnect's error — we're already in
		// a failure path, and the subsequent retry / fail-and-exit
		// will fire either way.
		_ = prov.Disconnect(ctx)
		return fmt.Errorf("connect succeeded but %w (provider=%s location=%s)", err, providerName, location)
	}
	exitIP := exitIPOrProbe(status.IP, observed)
	state.RecordTunnelUp(location, exitIP)
	state.Set(StateReady)
	log.Printf("tundler-tunnel: provider=%s tunnel up location=%s exit_ip=%s",
		providerName, location, exitIP)
	return nil
}

// exitIPOrProbe prefers the provider CLI's self-reported IP, falling back to
// the contract probe's observed egress IP when the CLI doesn't report one
// (OpenVPN-based providers like veepn/windscribe). Without this the recorded
// exit IP is empty and downstream consumers (e.g. the event hook) get nothing.
func exitIPOrProbe(reported, observed string) string {
	if reported != "" {
		return reported
	}
	return observed
}

// loginInitialWithRetry runs the BOOT login: it retries prov.Login until it
// succeeds or ctx is cancelled. Like connectInitialWithRetry, it NEVER exits
// the process — it stays alive and retries in-place with backoff.
//
// Rationale: a boot-login failure used to call failAndExit (exit 2 → kubelet
// container restart). But when login fails because the account is being
// THROTTLED (expressvpnctl "login with token" → "Timed out after 20s", not a
// credential error), a container restart just re-runs boot → another fresh
// login against the already-throttled account → the throttle persists and
// deepens. That self-reinforcing loop produced 700+ restart crashloops on the
// expressvpn pods, each restart a fresh login = exactly the re-login storm a
// shared-account heuristic punishes. The daemon-wedge case that originally
// justified failAndExit is already handled IN-PROCESS: Login() calls
// ensureDaemonResponsive (login-free daemon restart), so a container restart
// adds nothing the retry loop can't do without the re-login cost.
//
// State stays LoggingIn between attempts (→ /readyz 503, no traffic) while
// /livez stays 200 (process alive → kubelet never restarts the container).
// A genuine credential drift no longer crashloops loudly; instead the pod
// sits NotReady with the auth-failure counter on /status — observable, and
// strictly better than a storm that harms the whole account. Auth failures
// are recorded each attempt so that signal is preserved.
func loginInitialWithRetry(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, backoff func(attempt int) time.Duration) error {
	for attempt := 1; ; attempt++ {
		state.Set(StateLoggingIn)
		err := prov.Login(ctx)
		if err == nil {
			if attempt > 1 {
				log.Printf("tundler-tunnel: initial login succeeded on attempt %d (stayed up, no container restart)", attempt)
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		state.RecordAuthFailure(err.Error())
		wait := backoff(attempt)
		log.Printf("tundler-tunnel: initial login attempt %d failed for provider=%s: %v; retrying in %s (staying up, /livez 200 — no container restart, no re-login storm)",
			attempt, providerName, err, wait.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// connectInitialWithRetry runs the BOOT connect: it retries connectTunnel
// until it succeeds or ctx is cancelled. It NEVER re-logs-in and NEVER
// exits the process.
//
// Rationale: the session token is established once by the preceding
// Login(); a connect failure here is almost always transient (a throttled
// or mid-catalog-load daemon, a flaky exit). The old behaviour —
// failAndExit on the first failure — turned every such hiccup into a
// container restart, and the restart's fresh daemon forces a re-login.
// Re-login storms are exactly what trip a provider's shared-account /
// device-limit throttle, so we stay in-process and retry instead.
//
// State stays Connecting between attempts (→ /readyz 503, no traffic
// routed here) while /livez stays 200 (the process is alive and working).
// The only outer bound is the kubelet startup probe; if a provider outage
// outlasts it the resulting restart is graceful (gracefulDisconnect runs)
// — still far fewer logins than exiting on the first failure.
//
// backoff is injected so tests can drive it without real sleeps;
// production passes bootConnectBackoff.
func connectInitialWithRetry(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, baselineEgressIP string, backoff func(attempt int) time.Duration) error {
	for attempt := 1; ; attempt++ {
		err := connectTunnel(ctx, prov, state, providerName, excluded, baselineEgressIP)
		if err == nil {
			if attempt > 1 {
				log.Printf("tundler-tunnel: initial connect succeeded on attempt %d (stayed up, no re-login)", attempt)
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wait := backoff(attempt)
		log.Printf("tundler-tunnel: initial connect attempt %d failed: %v; retrying in %s (staying up, no re-login)",
			attempt, err, wait.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// bootConnectBackoff returns the wait before initial-connect retry n+1:
// exponential 1s, 2s, 4s, … capped at 5 min, with ±25% jitter so a fleet
// booting into a provider-wide outage doesn't re-hit the (possibly
// throttled) backend in lockstep. Gentle by design — each attempt forks
// the provider CLI (Locations/Connect), so we space attempts out rather
// than hammer a daemon that's already struggling.
//
// The 5-min cap (was 60s) exists for the account-saturation case: when
// more tunnels are provisioned than the provider account sustains
// concurrent sessions for, the surplus pods can NEVER connect — every
// Connect is a fresh session attempt the account rejects, and a tight
// 60s retry turned that into a re-login storm the provider flags as
// sharing (the chronic ExpressVPN churn-penalty spiral). Now the startup
// probe is /livez (no 10-min force-restart), so a shut-out pod simply
// stays NotReady and backs off to one attempt / 5 min — quiet enough to
// not trip the penalty, while still reclaiming a freed session slot
// within ~5 min. A healthy pod connects on attempt 1-2 and never reaches
// the cap.
func bootConnectBackoff(attempt int) time.Duration {
	const maxWait = 5 * time.Minute
	shift := attempt - 1
	if shift > 9 {
		shift = 9 // 1<<9 = 512s, clamped to maxWait below
	}
	base := time.Duration(1<<uint(shift)) * time.Second
	if base > maxWait {
		base = maxWait
	}
	jitter := time.Duration(rand.Int64N(int64(base)/2+1)) - base/4
	d := base + jitter
	if d < time.Second {
		d = time.Second
	}
	return d
}

// errRotationExhausted is returned by connectWithRetry when every attempt
// has failed. The caller (rotator) is expected to set state to Failed and
// rely on the liveness probe to trigger pod restart, mirroring the
// design-doc "failed-rotation handling" surrender path.
var errRotationExhausted = errors.New("rotation exhausted retry attempts")

// connectWithRetry tries connectTunnel up to maxAttempts times, picking a
// different location each attempt via a cumulative "recentlyFailed" set
// (so a single rotation doesn't retry the same broken location twice).
// Exponential backoff between attempts: 1s, 2s, 4s, 8s, ...
//
// `sleep` is injected so tests can pass a no-op. Production passes
// time.Sleep.
//
// Mirrors the design-doc pseudocode in "Failed-rotation handling":
//
//	for attempt in 1..ROTATION_RETRY_MAX:
//	    location = pickRandom(provider.Locations() \ excluded \ recentlyFailed)
//	    if connect(location) succeeds: state = Ready; return
//	    recentlyFailed.add(location)
//	    sleep(backoff)
//	// All attempts exhausted: caller transitions state = Failed.
func connectWithRetry(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string, maxAttempts int, sleep func(time.Duration), baselineEgressIP string) error {
	var recentlyFailed []string
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		state.Set(StateConnecting)
		if err := ensureLoggedIn(ctx, prov, providerName); err != nil {
			log.Printf("tundler-tunnel: rotation attempt %d/%d: %v", attempt, maxAttempts, err)
			if attempt < maxAttempts {
				sleep(retryBackoff(attempt))
			}
			continue
		}
		available := prov.Locations(ctx)
		combined := append([]string(nil), excluded...)
		combined = append(combined, recentlyFailed...)
		location, err := pickLocation(available, combined)
		if err != nil {
			// No more allowed locations — either all excluded by config,
			// or we've burned through them via recentlyFailed.
			return fmt.Errorf("attempt %d/%d: %w", attempt, maxAttempts, err)
		}
		log.Printf("tundler-tunnel: rotation attempt %d/%d to location=%s", attempt, maxAttempts, location)
		status := prov.Connect(ctx, location)
		if status.Connected {
			observed, err := verifyExitIPDiffers(ctx, baselineEgressIP)
			if err != nil {
				// Leak detected: treat as a failed attempt so the
				// rotator retries a different location (the failure
				// might be location-specific routing) rather than
				// jumping straight to fail-and-exit.
				_ = prov.Disconnect(ctx)
				recentlyFailed = append(recentlyFailed, location)
				log.Printf("tundler-tunnel: rotation attempt %d/%d FAILED contract (location=%s): %v",
					attempt, maxAttempts, location, err)
				if attempt < maxAttempts {
					sleep(retryBackoff(attempt))
				}
				continue
			}
			exitIP := exitIPOrProbe(status.IP, observed)
			state.RecordTunnelUp(location, exitIP)
			state.Set(StateReady)
			log.Printf("tundler-tunnel: rotation attempt %d/%d succeeded location=%s exit_ip=%s",
				attempt, maxAttempts, location, exitIP)
			return nil
		}
		recentlyFailed = append(recentlyFailed, location)
		log.Printf("tundler-tunnel: rotation attempt %d/%d failed (location=%s); will try another",
			attempt, maxAttempts, location)
		if attempt < maxAttempts {
			sleep(retryBackoff(attempt))
		}
	}
	return fmt.Errorf("%w (provider=%s, %d attempts)", errRotationExhausted, providerName, maxAttempts)
}

// retryBackoff returns the sleep before retry attempt n+1: 1s for after
// attempt 1, 2s for after attempt 2, 4s for after attempt 3, capped at
// 16s. Matches the design-doc pseudocode "sleep(backoff) # 1s, 2s, 4s".
func retryBackoff(attempt int) time.Duration {
	d := time.Duration(1<<(attempt-1)) * time.Second
	if d > 16*time.Second {
		return 16 * time.Second
	}
	return d
}
