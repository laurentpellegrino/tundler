package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
)

// noBackoff makes the retry loop spin without real sleeps.
func noBackoff(int) time.Duration { return time.Millisecond }

// TestSelectAccountWithRetryHealsInPlace exercises the core promise:
// a pod that boots with an out-of-range ordinal (accounts Secret behind
// the StatefulSet scale-up) records auth failures and then heals with
// NO restart once the operator fixes the Secret — because projected
// Secrets update in place and every attempt re-reads the directory.
func TestSelectAccountWithRetryHealsInPlace(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TUNDLER_ACCOUNTS_DIR", dir)
	t.Setenv("TUNDLER_ACCOUNTS", "")
	t.Setenv("POD_NAME", "tundler-tunnel-test-1") // ordinal 1
	t.Cleanup(accounts.Reset)

	// One account, one slot: ordinal 1 is out of range.
	writeTestAccount(t, dir, "00-main", "1")

	state := NewStateTracker("testprov")
	fixed := make(chan struct{})
	go func() {
		// "Operator" grows the account's capacity after a few failed
		// attempts — the projected-Secret edit, simulated.
		for state.Snapshot().AuthFailuresTotal < 2 {
			time.Sleep(time.Millisecond)
		}
		writeTestAccount(t, dir, "00-main", "2")
		close(fixed)
	}()

	acct, err := selectAccountWithRetry(context.Background(), state, "testprov", noBackoff)
	if err != nil {
		t.Fatalf("selectAccountWithRetry: %v", err)
	}
	<-fixed
	if acct == nil || acct.ID != "00-main" {
		t.Fatalf("account = %+v, want 00-main", acct)
	}
	if state.Snapshot().AuthFailuresTotal == 0 {
		t.Fatal("out-of-range attempts should have recorded auth failures")
	}
	if snap := state.Snapshot(); snap.AccountID != "" {
		t.Fatalf("SetAccount is main's job, not the retry loop's (got %q)", snap.AccountID)
	}
}

// TestSelectAccountWithRetryCtxCancel returns promptly with ctx.Err()
// when the pod shuts down mid-retry.
func TestSelectAccountWithRetryCtxCancel(t *testing.T) {
	t.Setenv("TUNDLER_ACCOUNTS_DIR", filepath.Join(t.TempDir(), "nonexistent"))
	t.Setenv("TUNDLER_ACCOUNTS", "")
	t.Setenv("POD_NAME", "")
	t.Cleanup(accounts.Reset)
	accounts.RegisterLegacyShim("cancelprov", func() []accounts.Account { return nil })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	state := NewStateTracker("cancelprov")
	if _, err := selectAccountWithRetry(ctx, state, "cancelprov", noBackoff); err == nil {
		t.Fatal("want ctx error after cancel")
	}
}

func writeTestAccount(t *testing.T, dir, id, slots string) {
	t.Helper()
	acctDir := filepath.Join(dir, id)
	if err := os.MkdirAll(acctDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, val := range map[string]string{"username": "u", "password": "p", "slots": slots} {
		if err := os.WriteFile(filepath.Join(acctDir, name), []byte(val), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
