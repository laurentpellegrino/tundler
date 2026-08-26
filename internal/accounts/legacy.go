package accounts

import (
	"fmt"
	"os"
	"strings"
)

// Shim builders for the two legacy env-var shapes providers used before
// the accounts model. Kept here so each provider's init() registration
// stays a one-liner; the ENV VAR NAMES still live in the provider
// packages that own them.

// LegacyEnvFields returns a shim synthesizing ONE unbounded account
// (ID "default", Slots 0 → serves every ordinal, i.e. today's
// shared-credential behavior) from a field→env-var mapping, e.g.
//
//	accounts.LegacyEnvFields(map[string]string{
//	    accounts.FieldUsername: "OVPN_USERNAME",
//	    accounts.FieldPassword: "OVPN_PASSWORD",
//	})
//
// The account is returned even when every var is empty: a missing
// credential then surfaces through Require's precise "create file X or
// set legacy env Y" error instead of a generic no-accounts error. The
// same mapping doubles as the Hint source for those errors.
func LegacyEnvFields(fields map[string]string) LegacyShim {
	return LegacyShim{
		Accounts: func() []Account {
			acct := Account{ID: "default", Slots: 0, Fields: map[string]string{}}
			for field, env := range fields {
				if v := strings.TrimSpace(os.Getenv(env)); v != "" {
					acct.Fields[field] = v
				}
			}
			return []Account{acct}
		},
		Hint: func(field string) string { return fields[field] },
	}
}

// LegacyPerPodEnv returns a shim reproducing the POD_<n>_* convention:
// it scans ordinals n = 0,1,2,… until the first gap, emitting one
// Slots=1 account ("pod-<n>") per ordinal whose EVERY field var is
// non-empty. prefixFmt is the env prefix with the ordinal slot, e.g.
// "POD_%d_VEEPN_"; fields maps canonical field name → env suffix.
//
// Under the block partition, N Slots=1 accounts in ordinal order map
// pod ordinal n to account pod-<n> — exactly today's behavior. Hint
// names THIS pod's var (POD_<ordinal>_…), resolved at error time so
// tests that move POD_NAME between cases stay accurate.
func LegacyPerPodEnv(prefixFmt string, fields map[string]string) LegacyShim {
	return LegacyShim{
		Accounts: func() []Account {
			var accts []Account
			for n := 0; ; n++ {
				prefix := fmt.Sprintf(prefixFmt, n)
				acct := Account{ID: fmt.Sprintf("pod-%d", n), Slots: 1, Fields: map[string]string{}}
				complete := true
				for field, suffix := range fields {
					v := strings.TrimSpace(os.Getenv(prefix + suffix))
					if v == "" {
						complete = false
						break
					}
					acct.Fields[field] = v
				}
				if !complete {
					return accts
				}
				accts = append(accts, acct)
			}
		},
		Hint: func(field string) string {
			suffix, ok := fields[field]
			if !ok {
				return ""
			}
			return fmt.Sprintf(prefixFmt, PodOrdinal()) + suffix
		},
	}
}
