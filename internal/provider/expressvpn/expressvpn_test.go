package expressvpn

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Locations() and ActiveLocation() must surface CLI failures as "no data"
// rather than parsing the error stdout as if it were the real result.
//
// expressvpnctl has its own internal 5-second timeout when querying its
// daemon; on timeout it writes literal text "Timed out after 5.002 sec" to
// stdout and exits non-zero. Pre-fix, Locations() did `out, _ := RunCmd(...)`
// then `strings.Fields(out)` and produced ["Timed", "out", "after", "5.002",
// "sec"] — the manager picked one of those at random as a location and tried
// to connect to it, wasting every connect attempt where the daemon happened
// to be slow. Post-fix the error must short-circuit to nil/"".
//
// We exercise the real `RunCmd` path by putting a stub `expressvpnctl` on
// PATH that fakes the timeout output.

func stubExpressvpnctl(t *testing.T, body string, exitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("PATH-stub trick assumes a POSIX shell")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "expressvpnctl")
	contents := "#!/bin/sh\ncat <<'__TUNDLER_STUB_EOF__'\n" +
		body + "\n__TUNDLER_STUB_EOF__\nexit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(script, []byte(contents), 0o755); err != nil {
		t.Fatalf("writing stub: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	// Defensive: tundler routes RunCmd through `ip netns exec` when this is
	// set in the runtime environment. Tests must run against the stub, not
	// inside a netns that doesn't exist.
	t.Setenv("TUNDLER_NETNS", "")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func TestLocationsReturnsNilOnCLIError(t *testing.T) {
	stubExpressvpnctl(t, "Timed out after 5.002 sec", 2)
	got := ExpressVPN{}.Locations(context.Background())
	if got != nil {
		t.Errorf("Locations() on CLI error = %v, want nil — pre-fix bug "+
			"would parse error text as locations", got)
	}
}

func TestLocationsParsesNormalOutput(t *testing.T) {
	stubExpressvpnctl(t, "smart\nuk-london\nfrance-paris-2", 0)
	got := ExpressVPN{}.Locations(context.Background())
	want := []string{"smart", "uk-london", "france-paris-2"}
	if len(got) != len(want) {
		t.Fatalf("Locations() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Locations()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestActiveLocationReturnsEmptyOnCLIError(t *testing.T) {
	stubExpressvpnctl(t, "Timed out after 5.002 sec", 2)
	got := ExpressVPN{}.ActiveLocation(context.Background())
	if got != "" {
		t.Errorf("ActiveLocation() on CLI error = %q, want \"\" — pre-fix "+
			"would surface CLI error text as the active region name", got)
	}
}

func TestActiveLocationReturnsValueOnSuccess(t *testing.T) {
	stubExpressvpnctl(t, "uk-london", 0)
	got := ExpressVPN{}.ActiveLocation(context.Background())
	if got != "uk-london" {
		t.Errorf("ActiveLocation() = %q, want %q", got, "uk-london")
	}
}
