package accounts

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	// envAccountsDir overrides where the projected Secret directory is
	// mounted. The default matches the deployment renderer's mount.
	envAccountsDir     = "TUNDLER_ACCOUNTS_DIR"
	defaultAccountsDir = "/etc/tundler/accounts"

	// envAccountsManifest is the ordered partition map emitted by the
	// deployment renderer: a CSV of <id>:<slots> entries, e.g.
	// "main:5,backup:3". Slots 0 marks a sole UNCAPPED account
	// ("main:0", the renderer's `slots: unlimited`) serving every
	// ordinal. When set it is AUTHORITATIVE for both account
	// ordering and slot counts — a directory listing is unordered and
	// a `slots` file can drift, so production always pins the
	// partition here (the env value doubles as the pod-roll trigger
	// when slots change). Local dev may omit it: the loader then falls
	// back to lexicographic directory order + per-directory `slots`
	// files (default 1).
	envAccountsManifest = "TUNDLER_ACCOUNTS"

	// envSingleAccountPrefix is the local-dev fallback: any
	// TUNDLER_ACCOUNT_<FIELD> vars present (and no accounts directory)
	// synthesize one account {ID: "env", Slots: 0} serving every
	// ordinal. Deliberately single-account — multi-account local runs
	// point TUNDLER_ACCOUNTS_DIR at a scratch directory instead.
	envSingleAccountPrefix = "TUNDLER_ACCOUNT_"

	// slotsFileName is the optional per-account-directory capacity
	// file used when TUNDLER_ACCOUNTS is unset. It is config, not a
	// credential, so it is excluded from Fields.
	slotsFileName = "slots"
)

// Sentinel errors, wrapped with context by the loader/partition.
var (
	ErrNoAccounts        = errors.New("no accounts configured")
	ErrOrdinalOutOfRange = errors.New("pod ordinal not covered by account slots")
	ErrBadSlots          = errors.New("invalid account slots")
)

// Pool is the ordered account list for this provider plus where it came
// from ("dir", "env" or "legacy" — logged at boot and exposed on
// /status so an operator can see mid-migration pods at a glance).
type Pool struct {
	Accounts []Account
	Source   string
}

// DirFromEnv returns the accounts directory currently in effect.
func DirFromEnv() string {
	if d := strings.TrimSpace(os.Getenv(envAccountsDir)); d != "" {
		return d
	}
	return defaultAccountsDir
}

// Load resolves the ordered account pool for providerName:
//
//  1. the projected Secret directory (production path);
//  2. TUNDLER_ACCOUNT_<FIELD> env (local dev);
//  3. the provider's registered legacy shim (deprecated env vars).
//
// An empty pool with a nil error means the provider registered no shim
// and nothing was configured — i.e. it requires no credentials
// (warp, psiphon).
func Load(providerName string) (*Pool, error) {
	accts, err := loadDir(DirFromEnv())
	if err != nil {
		return nil, err
	}
	if len(accts) > 0 {
		return &Pool{Accounts: accts, Source: "dir"}, nil
	}

	if accts := loadEnvSingle(); len(accts) > 0 {
		return &Pool{Accounts: accts, Source: "env"}, nil
	}

	if fn := legacyShim(providerName); fn != nil {
		accts := fn()
		if len(accts) > 0 {
			log.Printf("accounts: no %s dir — synthesized %d account(s) from legacy %s env vars (deprecated; migrate to the accounts directory, see README)",
				DirFromEnv(), len(accts), strings.ToUpper(providerName))
			return &Pool{Accounts: accts, Source: "legacy"}, nil
		}
		return &Pool{Source: "legacy"}, fmt.Errorf(
			"%w for provider %s: mount the accounts directory at %s or set the provider's legacy credential env vars",
			ErrNoAccounts, providerName, DirFromEnv())
	}

	// No directory, no env, no shim: this provider needs no account.
	return &Pool{Source: "none"}, nil
}

// loadDir scans one account per subdirectory. A missing directory is
// not an error (it just means "not the dir path"); a present-but-broken
// one is. Kubernetes projected-volume internals (`..data`,
// `..2026_…` timestamp dirs) are skipped, and symlinks are followed
// (kubelet materializes top-level entries as symlinks into `..data`).
func loadDir(dir string) ([]Account, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("accounts dir %s: %w", dir, err)
	}

	byID := make(map[string]Account)
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "..") {
			continue // kubelet atomic-writer artifacts
		}
		info, err := os.Stat(filepath.Join(dir, name)) // follows symlinks
		if err != nil || !info.IsDir() {
			continue
		}
		acct, err := loadAccountDir(filepath.Join(dir, name), name)
		if err != nil {
			return nil, err
		}
		byID[name] = acct
		ids = append(ids, name)
	}
	if len(ids) == 0 {
		return nil, nil
	}

	if manifest := strings.TrimSpace(os.Getenv(envAccountsManifest)); manifest != "" {
		return orderByManifest(byID, manifest, dir)
	}

	// No manifest: lexicographic ID order is the partition order.
	// Operators who care about ordering encode it in the name
	// (00-main, 01-backup).
	sort.Strings(ids)
	accts := make([]Account, 0, len(ids))
	for _, id := range ids {
		accts = append(accts, byID[id])
	}
	return accts, nil
}

// loadAccountDir reads every regular file of one account directory as a
// field (name lowercased), except the `slots` capacity file.
func loadAccountDir(dir, id string) (Account, error) {
	acct := Account{ID: id, Slots: 1, Fields: map[string]string{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return acct, fmt.Errorf("account %q: %w", id, err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "..") {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return acct, fmt.Errorf("account %q: read %s: %w", id, name, err)
		}
		if strings.EqualFold(name, slotsFileName) {
			n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil || n < 0 {
				return acct, fmt.Errorf("%w: account %q: slots file %q must be a non-negative integer (0 = unlimited, sole account only)",
					ErrBadSlots, id, strings.TrimSpace(string(raw)))
			}
			acct.Slots = n
			continue
		}
		acct.Fields[strings.ToLower(name)] = stripOneTrailingNewline(string(raw))
	}
	return acct, nil
}

// orderByManifest applies the authoritative TUNDLER_ACCOUNTS ordering:
// every listed id must exist as a directory (a listed-but-missing id is
// a hard error — the deployment shipped a partition the Secret doesn't
// back); directories NOT listed are ignored (staged additions).
// Manifest slots override any `slots` file.
func orderByManifest(byID map[string]Account, manifest, dir string) ([]Account, error) {
	var accts []Account
	for _, part := range strings.Split(manifest, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, slotsStr, found := strings.Cut(part, ":")
		id = strings.TrimSpace(id)
		if !found || id == "" {
			return nil, fmt.Errorf("%w: %s entry %q is not <id>:<slots>", ErrBadSlots, envAccountsManifest, part)
		}
		n, err := strconv.Atoi(strings.TrimSpace(slotsStr))
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%w: %s entry %q: slots must be a non-negative integer (0 = unlimited, sole account only)", ErrBadSlots, envAccountsManifest, part)
		}
		acct, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("%s lists account %q but %s/%s does not exist", envAccountsManifest, id, dir, id)
		}
		acct.Slots = n
		accts = append(accts, acct)
	}
	if len(accts) == 0 {
		return nil, fmt.Errorf("%w: %s is set but empty", ErrNoAccounts, envAccountsManifest)
	}
	// Slots 0 = "serves every ordinal" (the renderer's `slots:
	// unlimited` for uncapped providers) — only coherent for a sole
	// account, same rule ForOrdinal enforces for the legacy/env pools.
	if len(accts) > 1 {
		for _, a := range accts {
			if a.Slots == 0 {
				return nil, fmt.Errorf("%w: %s lists account %q with slots 0 (unlimited) next to others — an uncapped account must be the sole account", ErrBadSlots, envAccountsManifest, a.ID)
			}
		}
	}
	return accts, nil
}

// loadEnvSingle synthesizes the single local-dev account from
// TUNDLER_ACCOUNT_<FIELD> env vars.
func loadEnvSingle() []Account {
	fields := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(k, envSingleAccountPrefix) {
			continue
		}
		field := strings.ToLower(strings.TrimPrefix(k, envSingleAccountPrefix))
		if field == "" || v == "" {
			continue
		}
		fields[field] = v
	}
	if len(fields) == 0 {
		return nil
	}
	return []Account{{ID: "env", Slots: 0, Fields: fields}}
}

// stripOneTrailingNewline removes exactly one trailing "\n" or "\r\n".
// Secret files conventionally end with a newline; stripping more would
// mangle values that legitimately end in blank lines.
func stripOneTrailingNewline(s string) string {
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}

// TotalSlots sums the pool's capacity; -1 means unbounded (a
// single-account legacy/env pool that serves every ordinal).
func (p *Pool) TotalSlots() int {
	total := 0
	for _, a := range p.Accounts {
		if a.Slots == 0 {
			return -1
		}
		total += a.Slots
	}
	return total
}

// ForOrdinal maps a pod ordinal to the account whose contiguous slot
// block contains it: accounts a(5), b(3) → ordinals 0-4→a, 5-7→b.
//
// A single account with Slots==0 serves every ordinal — that preserves
// today's "all pods share the one env credential" behavior byte-for-
// byte for the legacy/env fallbacks, and is how the renderer expresses
// an uncapped provider (`slots: unlimited` → "<id>:0"). Slots==0
// anywhere else is a configuration error.
func (p *Pool) ForOrdinal(ord int) (*Account, error) {
	if len(p.Accounts) == 0 {
		return nil, ErrNoAccounts
	}
	if ord < 0 {
		return nil, fmt.Errorf("%w: negative ordinal %d", ErrOrdinalOutOfRange, ord)
	}
	if len(p.Accounts) == 1 && p.Accounts[0].Slots == 0 {
		return &p.Accounts[0], nil
	}

	cursor := 0
	for i := range p.Accounts {
		a := &p.Accounts[i]
		if a.Slots < 1 {
			return nil, fmt.Errorf("%w: account %q has slots=%d (0 = unlimited is only valid for a sole account)",
				ErrBadSlots, a.ID, a.Slots)
		}
		if ord < cursor+a.Slots {
			return a, nil
		}
		cursor += a.Slots
	}

	// Out of range: the error prints the full slot table so the fix
	// (grow an account's slots, or shrink the StatefulSet) is obvious
	// from the log line alone.
	table := make([]string, len(p.Accounts))
	for i, a := range p.Accounts {
		table[i] = fmt.Sprintf("%s:%d", a.ID, a.Slots)
	}
	return nil, fmt.Errorf("%w: ordinal %d >= %d total slots (%s) — check account slots vs StatefulSet replicas",
		ErrOrdinalOutOfRange, ord, cursor, strings.Join(table, ", "))
}
