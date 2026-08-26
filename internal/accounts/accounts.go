// Package accounts is tundler's provider-credential model: a provider
// has one or more ACCOUNTS (each a named bag of credential fields with
// an explicit concurrent-session capacity), and every pod deterministically
// owns exactly one of them, derived from its StatefulSet ordinal.
//
// Why this exists: the fleet's worst production incidents were
// session-starved shared accounts — more tunnel pods than the one
// account sustains concurrent sessions (see the rationale block in
// cmd/tundler-tunnel/connect.go around loginInitialWithRetry). The
// per-account `Slots` capacity turns that invariant, which used to live
// in deployment-YAML comments, into enforced configuration: pods are
// block-partitioned over accounts in declared order, so account a
// (slots=5) + account b (slots=3) serve ordinals 0-4 and 5-7
// respectively, and an ordinal beyond the declared capacity is a loud,
// actionable boot error instead of a login storm.
//
// Delivery: accounts arrive as a projected Secret directory
// (/etc/tundler/accounts/<account-id>/<field>, one file per field) —
// files, not env, because the container entrypoint's line-oriented
// printenv|grep filter truncates multi-line values (PEMs) to their
// first line, which is exactly the bug that forced cyberghost's old
// bespoke /etc/cyberghost/creds path. See loader.go for the full
// resolution order (directory → local-dev env → legacy env shim).
//
// This package is a leaf: it imports nothing from this repo, so both
// provider packages and cmd/tundler-tunnel can depend on it freely.
package accounts

import (
	"fmt"
	"strings"
)

// Canonical field names. These are simultaneously the file names under
// the account directory, the OpenBao property names the deployment
// renderer fetches, and the suffixes of the TUNDLER_ACCOUNT_<FIELD>
// local-dev env fallback — one vocabulary end to end.
const (
	FieldUsername       = "username"
	FieldPassword       = "password"
	FieldToken          = "token"
	FieldActivationCode = "activation_code"
	FieldCertificate    = "certificate"
	FieldKey            = "key"
	FieldPrivateKey     = "private_key"
	FieldPrivateKeys    = "private_keys" // comma pool; legacy surfshark-WireGuard shim only
	FieldAddress        = "address"
	FieldAddress6       = "address6"
)

// Account is one provider identity: credentials plus capacity.
type Account struct {
	// ID is the account directory name — an operator label, never a
	// secret, safe to log and to expose on /status.
	ID string

	// Slots is how many pods this account serves concurrently (the
	// provider's device/session cap for it). 0 means "all ordinals" —
	// produced by the single-account legacy/env fallbacks (preserving
	// today's shared-credential behavior exactly) and by the renderer
	// for uncapped providers (`slots: unlimited` → "<id>:0").
	Slots int

	// Fields maps field name (lowercased file name) → value. Values
	// keep their exact bytes except that the loader strips one trailing
	// newline (Secret files conventionally end with one; PEM blocks are
	// unharmed because they terminate with their own newline).
	Fields map[string]string
}

// Field returns the raw value of a field — PEM-safe, no trimming beyond
// the loader's single trailing-newline strip. ok=false when the field
// is absent or empty.
func (a *Account) Field(name string) (string, bool) {
	v, ok := a.Fields[name]
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// Line returns a single-line field (username, password, token, …) with
// surrounding whitespace trimmed. ok=false when absent or blank.
func (a *Account) Line(name string) (string, bool) {
	v, ok := a.Fields[name]
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return v, true
}

// Require returns Line(name) or an error that tells the operator
// exactly what to fix: the account, the missing field, the file the
// loader looked for, and — when non-empty — the legacy env var that
// still works during the migration window. This message surfaces on
// /status via the auth-failure fields, so it must be self-contained.
func (a *Account) Require(name, legacyHint string) (string, error) {
	if v, ok := a.Line(name); ok {
		return v, nil
	}
	msg := fmt.Sprintf("account %q: missing field %q (file %s/%s/%s",
		a.ID, name, DirFromEnv(), a.ID, name)
	if legacyHint != "" {
		msg += fmt.Sprintf(", or legacy env %s", legacyHint)
	}
	return "", fmt.Errorf("%s)", msg)
}

// RequireRaw is Require for multi-line fields (PEM certificates/keys):
// same error contract, no whitespace trimming.
func (a *Account) RequireRaw(name, legacyHint string) (string, error) {
	if v, ok := a.Field(name); ok {
		return v, nil
	}
	return a.Require(name, legacyHint) // reuse the error message
}
