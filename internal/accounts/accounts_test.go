package accounts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeAccount lays out one account directory in dir.
func writeAccount(t *testing.T, dir, id string, fields map[string]string) {
	t.Helper()
	acctDir := filepath.Join(dir, id)
	if err := os.MkdirAll(acctDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, val := range fields {
		if err := os.WriteFile(filepath.Join(acctDir, name), []byte(val), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func testEnv(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("TUNDLER_ACCOUNTS_DIR", dir)
	t.Setenv("TUNDLER_ACCOUNTS", "")
	t.Setenv("POD_NAME", "")
	t.Cleanup(Reset)
	Reset()
}

func TestLoadDirLexicographicOrderAndSlotsFile(t *testing.T) {
	dir := t.TempDir()
	testEnv(t, dir)
	// Written out of order on purpose; 00-/01- prefixes carry ordering.
	writeAccount(t, dir, "01-backup", map[string]string{"username": "u2\n", "password": "p2\n", "slots": "3\n"})
	writeAccount(t, dir, "00-main", map[string]string{"username": "u1\n", "password": "p1\n", "slots": "5\n"})

	pool, err := Load("pia")
	if err != nil {
		t.Fatal(err)
	}
	if pool.Source != "dir" {
		t.Fatalf("source = %q, want dir", pool.Source)
	}
	if len(pool.Accounts) != 2 || pool.Accounts[0].ID != "00-main" || pool.Accounts[1].ID != "01-backup" {
		t.Fatalf("wrong order: %+v", pool.Accounts)
	}
	if pool.Accounts[0].Slots != 5 || pool.Accounts[1].Slots != 3 {
		t.Fatalf("slots not read: %+v", pool.Accounts)
	}
	if u, _ := pool.Accounts[0].Line(FieldUsername); u != "u1" {
		t.Fatalf("username = %q", u)
	}
	if _, ok := pool.Accounts[0].Field("slots"); ok {
		t.Fatal("slots capacity file leaked into Fields")
	}
}

func TestLoadDirSkipsProjectedVolumeArtifacts(t *testing.T) {
	dir := t.TempDir()
	testEnv(t, dir)
	writeAccount(t, dir, "a", map[string]string{"username": "u", "password": "p"})
	// kubelet atomic-writer artifacts at the mount root.
	if err := os.MkdirAll(filepath.Join(dir, "..2026_08_12_data"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeAccount(t, dir, "..data", map[string]string{"username": "ghost"})

	pool, err := Load("pia")
	if err != nil {
		t.Fatal(err)
	}
	if len(pool.Accounts) != 1 || pool.Accounts[0].ID != "a" {
		t.Fatalf("artifacts not skipped: %+v", pool.Accounts)
	}
}

func TestLoadDirFollowsSymlinkedAccountDirs(t *testing.T) {
	// kubelet materializes top-level entries as symlinks into ..data;
	// the loader must follow them, not skip them as non-dirs.
	dir := t.TempDir()
	testEnv(t, dir)
	data := filepath.Join(dir, "..data")
	writeAccount(t, data, "a", map[string]string{"username": "u", "password": "p"})
	if err := os.Symlink(filepath.Join(data, "a"), filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}

	pool, err := Load("pia")
	if err != nil {
		t.Fatal(err)
	}
	if len(pool.Accounts) != 1 || pool.Accounts[0].ID != "a" {
		t.Fatalf("symlinked account not loaded: %+v", pool.Accounts)
	}
}

func TestTrailingNewlineStripPreservesPEM(t *testing.T) {
	dir := t.TempDir()
	testEnv(t, dir)
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	writeAccount(t, dir, "a", map[string]string{
		"certificate": pem,
		"username":    "user\r\n",
	})

	pool, err := Load("cyberghost")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := pool.Accounts[0].Field(FieldCertificate)
	want := strings.TrimSuffix(pem, "\n")
	if got != want {
		t.Fatalf("PEM mangled:\n%q\nwant\n%q", got, want)
	}
	if u, _ := pool.Accounts[0].Line(FieldUsername); u != "user" {
		t.Fatalf("CRLF not stripped: %q", u)
	}
}

func TestManifestAuthoritativeOrderAndSlots(t *testing.T) {
	dir := t.TempDir()
	testEnv(t, dir)
	// Lexicographic order would be backup, main — the manifest must win.
	writeAccount(t, dir, "backup", map[string]string{"username": "b", "slots": "9"})
	writeAccount(t, dir, "main", map[string]string{"username": "m"})
	writeAccount(t, dir, "staged", map[string]string{"username": "s"}) // unlisted → ignored
	t.Setenv("TUNDLER_ACCOUNTS", "main:5, backup:3")

	pool, err := Load("pia")
	if err != nil {
		t.Fatal(err)
	}
	if len(pool.Accounts) != 2 || pool.Accounts[0].ID != "main" || pool.Accounts[1].ID != "backup" {
		t.Fatalf("manifest order not applied: %+v", pool.Accounts)
	}
	// Manifest slots override the drifted slots file (9).
	if pool.Accounts[0].Slots != 5 || pool.Accounts[1].Slots != 3 {
		t.Fatalf("manifest slots not applied: %+v", pool.Accounts)
	}
}

func TestManifestUnlimitedSoleAccount(t *testing.T) {
	// "main:0" is the renderer's `slots: unlimited` (uncapped provider):
	// the sole account serves every ordinal, and scaling max_tunnels
	// never changes the env value.
	dir := t.TempDir()
	testEnv(t, dir)
	writeAccount(t, dir, "main", map[string]string{"username": "m"})
	t.Setenv("TUNDLER_ACCOUNTS", "main:0")

	pool, err := Load("windscribe")
	if err != nil {
		t.Fatal(err)
	}
	for _, ord := range []int{0, 7, 42} {
		acct, err := pool.ForOrdinal(ord)
		if err != nil || acct.ID != "main" {
			t.Fatalf("ordinal %d: got %v, %v; want main", ord, acct, err)
		}
	}
	if pool.TotalSlots() != -1 {
		t.Fatalf("TotalSlots = %d, want -1 (unbounded)", pool.TotalSlots())
	}
}

func TestManifestUnlimitedNextToCappedIsError(t *testing.T) {
	dir := t.TempDir()
	testEnv(t, dir)
	writeAccount(t, dir, "main", map[string]string{"username": "m"})
	writeAccount(t, dir, "backup", map[string]string{"username": "b"})
	t.Setenv("TUNDLER_ACCOUNTS", "main:0,backup:3")

	if _, err := Load("pia"); !errors.Is(err, ErrBadSlots) {
		t.Fatalf("want ErrBadSlots for unlimited next to capped, got %v", err)
	}
}

func TestManifestMissingDirIsHardError(t *testing.T) {
	dir := t.TempDir()
	testEnv(t, dir)
	writeAccount(t, dir, "main", map[string]string{"username": "m"})
	t.Setenv("TUNDLER_ACCOUNTS", "main:5,ghost:3")

	if _, err := Load("pia"); err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("want hard error naming the missing account, got %v", err)
	}
}

func TestBadSlotsFile(t *testing.T) {
	dir := t.TempDir()
	testEnv(t, dir)
	writeAccount(t, dir, "a", map[string]string{"username": "u", "slots": "zero"})

	if _, err := Load("pia"); !errors.Is(err, ErrBadSlots) {
		t.Fatalf("want ErrBadSlots, got %v", err)
	}
}

func TestEnvSingleAccountFallback(t *testing.T) {
	testEnv(t, filepath.Join(t.TempDir(), "nonexistent"))
	t.Setenv("TUNDLER_ACCOUNT_USERNAME", "devuser")
	t.Setenv("TUNDLER_ACCOUNT_PASSWORD", "devpass")

	pool, err := Load("pia")
	if err != nil {
		t.Fatal(err)
	}
	if pool.Source != "env" || len(pool.Accounts) != 1 {
		t.Fatalf("pool = %+v", pool)
	}
	a := pool.Accounts[0]
	if a.ID != "env" || a.Slots != 0 {
		t.Fatalf("account = %+v", a)
	}
	if u, _ := a.Line(FieldUsername); u != "devuser" {
		t.Fatalf("username = %q", u)
	}
}

func TestLegacyShimPrecedenceAndDeprecation(t *testing.T) {
	testEnv(t, filepath.Join(t.TempDir(), "nonexistent"))
	RegisterLegacyShim("fakeprov", LegacyShim{Accounts: func() []Account {
		if v := os.Getenv("FAKEPROV_USERNAME"); v != "" {
			return []Account{{ID: "default", Slots: 0, Fields: map[string]string{FieldUsername: v}}}
		}
		return nil
	}})
	t.Setenv("FAKEPROV_USERNAME", "legacyuser")

	pool, err := Load("fakeprov")
	if err != nil {
		t.Fatal(err)
	}
	if pool.Source != "legacy" || len(pool.Accounts) != 1 {
		t.Fatalf("pool = %+v", pool)
	}

	// Shim registered but env absent → actionable ErrNoAccounts.
	t.Setenv("FAKEPROV_USERNAME", "")
	if _, err := Load("fakeprov"); !errors.Is(err, ErrNoAccounts) {
		t.Fatalf("want ErrNoAccounts, got %v", err)
	}

	// Directory beats the shim when both exist.
	dir := t.TempDir()
	t.Setenv("TUNDLER_ACCOUNTS_DIR", dir)
	t.Setenv("FAKEPROV_USERNAME", "legacyuser")
	writeAccount(t, dir, "a", map[string]string{"username": "diruser"})
	pool, err = Load("fakeprov")
	if err != nil {
		t.Fatal(err)
	}
	if pool.Source != "dir" {
		t.Fatalf("dir should take precedence, got %q", pool.Source)
	}
}

func TestNoAccountRequiredProvider(t *testing.T) {
	testEnv(t, filepath.Join(t.TempDir(), "nonexistent"))
	acct, err := Select("warp", 0)
	if err != nil || acct != nil {
		t.Fatalf("want (nil, nil) for account-less provider, got (%+v, %v)", acct, err)
	}
}

func TestForOrdinalBlockPartition(t *testing.T) {
	pool := &Pool{Accounts: []Account{
		{ID: "a", Slots: 5},
		{ID: "b", Slots: 3},
	}}
	cases := []struct {
		ord  int
		want string
	}{
		{0, "a"}, {4, "a"}, {5, "b"}, {7, "b"},
	}
	for _, c := range cases {
		got, err := pool.ForOrdinal(c.ord)
		if err != nil {
			t.Fatalf("ForOrdinal(%d): %v", c.ord, err)
		}
		if got.ID != c.want {
			t.Errorf("ForOrdinal(%d) = %s, want %s", c.ord, got.ID, c.want)
		}
	}

	// Out of range: error prints the slot table.
	_, err := pool.ForOrdinal(8)
	if !errors.Is(err, ErrOrdinalOutOfRange) {
		t.Fatalf("want ErrOrdinalOutOfRange, got %v", err)
	}
	if !strings.Contains(err.Error(), "a:5") || !strings.Contains(err.Error(), "b:3") {
		t.Fatalf("error lacks slot table: %v", err)
	}

	if _, err := pool.ForOrdinal(-1); !errors.Is(err, ErrOrdinalOutOfRange) {
		t.Fatalf("negative ordinal: %v", err)
	}
}

func TestForOrdinalUnboundedSingleAccount(t *testing.T) {
	pool := &Pool{Accounts: []Account{{ID: "env", Slots: 0}}}
	for _, ord := range []int{0, 7, 99} {
		got, err := pool.ForOrdinal(ord)
		if err != nil || got.ID != "env" {
			t.Fatalf("ForOrdinal(%d) = (%v, %v)", ord, got, err)
		}
	}
	if pool.TotalSlots() != -1 {
		t.Fatalf("TotalSlots = %d, want -1", pool.TotalSlots())
	}

	// Slots==0 mixed with real accounts is a config error.
	mixed := &Pool{Accounts: []Account{{ID: "x", Slots: 0}, {ID: "y", Slots: 2}}}
	if _, err := mixed.ForOrdinal(0); !errors.Is(err, ErrBadSlots) {
		t.Fatalf("want ErrBadSlots for mixed Slots=0, got %v", err)
	}
}

func TestSelectAndCurrent(t *testing.T) {
	dir := t.TempDir()
	testEnv(t, dir)
	writeAccount(t, dir, "00-main", map[string]string{"username": "u1", "slots": "1"})
	writeAccount(t, dir, "01-backup", map[string]string{"username": "u2", "slots": "1"})

	acct, err := Select("pia", 1)
	if err != nil {
		t.Fatal(err)
	}
	if acct.ID != "01-backup" {
		t.Fatalf("Select ordinal 1 = %s", acct.ID)
	}
	cur, err := Current("pia")
	if err != nil || cur.ID != "01-backup" {
		t.Fatalf("Current = (%+v, %v)", cur, err)
	}
	if Source() != "dir" {
		t.Fatalf("Source = %q", Source())
	}

	// Lazy Current after Reset resolves via PodOrdinal (POD_NAME unset → 0).
	Reset()
	cur, err = Current("pia")
	if err != nil || cur.ID != "00-main" {
		t.Fatalf("lazy Current = (%+v, %v)", cur, err)
	}
}

func TestRequireErrorNamesFileAndLegacyHint(t *testing.T) {
	// The hint comes from the registered shim, stamped by Load onto
	// every account — DIR-sourced ones included, so mid-migration
	// errors name both worlds.
	dir := t.TempDir()
	testEnv(t, dir)
	RegisterLegacyShim("hintprov", LegacyEnvFields(map[string]string{
		FieldUsername: "HINTPROV_USERNAME",
	}))
	writeAccount(t, dir, "00-main", map[string]string{"password": "p"})

	pool, err := Load("hintprov")
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Accounts[0].Require(FieldUsername)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"00-main", "username", dir + "/00-main/username", "HINTPROV_USERNAME"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}

	// An Account constructed directly (no Load) has no hint — the
	// error simply drops the legacy clause.
	a := Account{ID: "x", Fields: map[string]string{}}
	if _, err := a.Require(FieldUsername); err == nil || strings.Contains(err.Error(), "legacy") {
		t.Fatalf("hintless error should omit the legacy clause, got %v", err)
	}
}

func TestPodOrdinal(t *testing.T) {
	cases := []struct {
		pod  string
		want int
	}{
		{"tundler-tunnel-veepn-12", 12},
		{"tundler-tunnel-mullvad-0", 0},
		{"no-ordinal-suffix-x", 0},
		{"", 0},
	}
	for _, c := range cases {
		t.Setenv("POD_NAME", c.pod)
		if got := PodOrdinal(); got != c.want {
			t.Errorf("PodOrdinal(%q) = %d, want %d", c.pod, got, c.want)
		}
	}
}
