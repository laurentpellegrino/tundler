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

// LegacyShim is a provider's bridge to its pre-accounts credential
// source. Accounts synthesizes the pool from the deprecated env vars
// (or files); Hint names, for one field, where that source lives (an
// env var name, or cyberghost's creds-file path) so Require errors can
// point mid-migration operators at both worlds. Registering the hint
// HERE — next to the map the shim itself reads — keeps the env-var
// vocabulary in one place instead of repeating it at every Require
// call site.
type LegacyShim struct {
	Accounts func() []Account
	Hint     func(field string) string
}

var (
	shimMu sync.Mutex
	shims  = map[string]LegacyShim{}
)

// RegisterLegacyShim installs the deprecated-env synthesizer for a
// provider. Call once from the provider package's init().
func RegisterLegacyShim(providerName string, s LegacyShim) {
	shimMu.Lock()
	defer shimMu.Unlock()
	shims[providerName] = s
}

func legacyShim(providerName string) (LegacyShim, bool) {
	shimMu.Lock()
	defer shimMu.Unlock()
	s, ok := shims[providerName]
	return s, ok
}
