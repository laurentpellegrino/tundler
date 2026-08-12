package accounts

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"sync"
)

// One process runs exactly one provider (the per-provider tunnel-pod
// model), so the selected account is package state — the same shape as
// the provider packages' own loggedIn/serverCache state and
// cmd/tundler-tunnel's lastReloginUnix. Providers reach it through
// Current() instead of threading an Account through every call path,
// which keeps the provider.VPNProvider interface untouched.

var (
	selMu      sync.Mutex
	selDone    bool
	selAccount *Account
	selSource  string
)

// Select loads the pool, applies the ordinal block partition, stores
// the result as the process-wide current account, and returns it.
// Called once from cmd/tundler-tunnel boot (with retries — a projected
// Secret that appears or is fixed later must heal the pod in place).
//
// A (nil, nil) return means the provider requires no account
// (warp, psiphon: no directory, no env, no registered shim).
func Select(providerName string, ordinal int) (*Account, error) {
	selMu.Lock()
	defer selMu.Unlock()
	return selectLocked(providerName, ordinal)
}

func selectLocked(providerName string, ordinal int) (*Account, error) {
	pool, err := Load(providerName)
	if err != nil {
		return nil, err
	}
	if len(pool.Accounts) == 0 {
		// Load already errored for credentialed providers (shim
		// registered, nothing found); reaching here means "no account
		// required".
		selDone, selAccount, selSource = true, nil, pool.Source
		return nil, nil
	}
	acct, err := pool.ForOrdinal(ordinal)
	if err != nil {
		return nil, fmt.Errorf("provider %s: %w", providerName, err)
	}
	selDone, selAccount, selSource = true, acct, pool.Source
	return acct, nil
}

// Current returns the selected account. When Select was never called
// (unit tests, standalone library use) it resolves FRESH on every call
// via PodOrdinal() — without pinning — which preserves today's
// "providers re-read env at each Login/Connect" behavior for tests that
// flip credential env vars between cases. Production pins the choice
// once at boot via Select.
func Current(providerName string) (*Account, error) {
	selMu.Lock()
	defer selMu.Unlock()
	var acct *Account
	if selDone {
		acct = selAccount
	} else {
		pool, err := Load(providerName)
		if err != nil {
			return nil, err
		}
		if len(pool.Accounts) > 0 {
			if acct, err = pool.ForOrdinal(PodOrdinal()); err != nil {
				return nil, fmt.Errorf("provider %s: %w", providerName, err)
			}
		}
	}
	if acct == nil {
		return nil, fmt.Errorf("%w for provider %s", ErrNoAccounts, providerName)
	}
	return acct, nil
}

// Source reports where the current selection came from
// ("dir" | "env" | "legacy" | "none" | "" when nothing selected yet).
func Source() string {
	selMu.Lock()
	defer selMu.Unlock()
	return selSource
}

// Reset clears the selection so the next Select/Current re-reads the
// directory — used by tests and by the boot retry loop (projected
// Secrets update in place, so a fixed Secret heals the pod with zero
// restarts and zero logins).
func Reset() {
	selMu.Lock()
	defer selMu.Unlock()
	selDone, selAccount, selSource = false, nil, ""
}

// podOrdinalRe extracts the ordinal suffix from a StatefulSet pod name
// (tundler-tunnel-veepn-3 → 3). Consolidates the three private copies
// that lived in the mullvad, veepn and cyberghost packages.
var podOrdinalRe = regexp.MustCompile(`-(\d+)$`)

// PodOrdinal returns this pod's StatefulSet ordinal from POD_NAME
// (downward API), or 0 when POD_NAME is unset or has no -N suffix —
// the local-dev fallback every per-pod provider already used.
func PodOrdinal() int {
	pod := os.Getenv("POD_NAME")
	if pod == "" {
		return 0
	}
	if m := podOrdinalRe.FindStringSubmatch(pod); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n
		}
	}
	return 0
}
