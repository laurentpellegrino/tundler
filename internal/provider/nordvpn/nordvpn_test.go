package nordvpn

import (
	"context"
	"errors"
	"os"
	"testing"
)

// TestMain keeps every test away from a real nordvpn client: on a machine
// with one logged in, Connect would open (or be refused) a real tunnel.
func TestMain(m *testing.M) {
	runCmd = func(context.Context, string, ...string) (string, error) {
		return "", errors.New("nordvpn CLI disabled in tests")
	}
	os.Exit(m.Run())
}

func resetActiveLocation(t *testing.T) {
	t.Helper()
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
}

// TestConnectStoresLocation pins the contract that Connect stores
// whatever was passed in (an entry from Locations()). RunCmd shells
// out to `nordvpn`; in tests runCmd is stubbed to return an error
// that quiet() swallows, and the location-mutation step that
// follows runs unconditionally. That's the behaviour we want: the
// invariant is "Connect was asked to connect to X, so X is the active
// location", not "we read X back from the CLI".
func TestConnectStoresLocation(t *testing.T) {
	resetActiveLocation(t)
	t.Cleanup(func() { resetActiveLocation(t) })

	_ = NordVPN{}.Connect(context.Background(), "Tunisia")

	activeMu.RLock()
	got := activeLocation
	activeMu.RUnlock()
	if got != "Tunisia" {
		t.Fatalf("activeLocation after Connect(\"Tunisia\") = %q, want %q", got, "Tunisia")
	}
}

// Apostrophes / punctuation must round-trip verbatim — any
// normalisation (space→underscore, strip-apostrophe) would break the
// pool ↔ Status.Location match for entries like NordVPN's
// "Lao_Peoples_Democratic_Republic" versus the CLI's
// "Lao People's Democratic Republic". The store-and-return design
// sidesteps the problem by never re-deriving the string.
func TestConnectStoresLocationVerbatim(t *testing.T) {
	resetActiveLocation(t)
	t.Cleanup(func() { resetActiveLocation(t) })

	want := "Lao_Peoples_Democratic_Republic"
	_ = NordVPN{}.Connect(context.Background(), want)

	activeMu.RLock()
	got := activeLocation
	activeMu.RUnlock()
	if got != want {
		t.Fatalf("activeLocation = %q, want %q (no normalisation)", got, want)
	}
}

// Connect("") clears activeLocation rather than holding onto a stale
// previous value. The caller chose not to pin a location; we don't
// pretend to know one.
func TestConnectEmptyLocationClears(t *testing.T) {
	resetActiveLocation(t)
	t.Cleanup(func() { resetActiveLocation(t) })

	activeMu.Lock()
	activeLocation = "Tunisia"
	activeMu.Unlock()

	_ = NordVPN{}.Connect(context.Background(), "")

	activeMu.RLock()
	got := activeLocation
	activeMu.RUnlock()
	if got != "" {
		t.Fatalf("activeLocation after Connect(\"\") = %q, want empty", got)
	}
}

func TestDisconnectClearsActiveLocation(t *testing.T) {
	resetActiveLocation(t)
	t.Cleanup(func() { resetActiveLocation(t) })

	activeMu.Lock()
	activeLocation = "Tunisia"
	activeMu.Unlock()

	_ = NordVPN{}.Disconnect(context.Background())

	activeMu.RLock()
	got := activeLocation
	activeMu.RUnlock()
	if got != "" {
		t.Fatalf("activeLocation after Disconnect = %q, want empty", got)
	}
}

// ActiveLocation must gate on Connected(): a stale value from a
// prior session should not leak out once the tunnel is gone. In this
// test environment the `nordvpn` CLI is absent, so Connected()
// returns false and the gate must hide the in-memory value.
func TestActiveLocationEmptyWhenDisconnected(t *testing.T) {
	resetActiveLocation(t)
	t.Cleanup(func() { resetActiveLocation(t) })

	activeMu.Lock()
	activeLocation = "Tunisia"
	activeMu.Unlock()

	if got := (NordVPN{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
}

func TestThrottledOutput(t *testing.T) {
	refusal := "Connecting to Portugal #148 (pt148.nordvpn.com)\nToo many connection attempts. Wait a while before trying again. Retrying now can make the waiting period longer."
	if !throttledOutput(refusal) {
		t.Fatal("the daemon's refusal must read as throttled")
	}
	for _, out := range []string{"", "You are connected to Portugal #148 (pt148.nordvpn.com)!", "Whoops! Connection failed. Please try again."} {
		if throttledOutput(out) {
			t.Fatalf("%q must not read as throttled", out)
		}
	}
}
