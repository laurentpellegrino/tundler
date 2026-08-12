package accounts

import "sync"

// Legacy shims synthesize the account pool from a provider's
// PRE-accounts env vars (PRIVATEINTERNETACCESS_USERNAME,
// POD_<n>_MULLVAD_PRIVATE_KEY, …) so the tundler image and the
// deployment manifests can roll independently: a pod that boots without
// an accounts directory keeps working exactly as before, with one
// deprecation log line.
//
// The shim lives WITH the provider package that owns the env-var names
// (registered from its init(), right next to provider.Registry), so
// deleting a provider deletes its shim and this package never learns
// provider specifics.
//
// Per-pod providers (mullvad, veepn, cyberghost) scan POD_<n>_* for
// n = 0,1,2,… until the first gap and emit one Slots=1 account per
// ordinal — which reproduces today's ordinal→identity mapping exactly
// under the block partition.

var (
	shimMu sync.Mutex
	shims  = map[string]func() []Account{}
)

// RegisterLegacyShim installs the deprecated-env synthesizer for a
// provider. Call once from the provider package's init().
func RegisterLegacyShim(providerName string, fn func() []Account) {
	shimMu.Lock()
	defer shimMu.Unlock()
	shims[providerName] = fn
}

func legacyShim(providerName string) func() []Account {
	shimMu.Lock()
	defer shimMu.Unlock()
	return shims[providerName]
}
