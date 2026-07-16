package proxy

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

// The whole point of the rotation is that no single fingerprint carries the
// fleet and that a given tunnel keeps a STABLE identity. These tests guard
// both, plus that every profile is a real, non-empty preset.

func TestPickProfileIsStable(t *testing.T) {
	key := "tundler-tunnel-expressvpn-3"
	first := PickProfile(key)
	for i := 0; i < 100; i++ {
		if got := PickProfile(key); got.Str() != first.Str() {
			t.Fatalf("PickProfile(%q) not stable: %s != %s", key, got.Str(), first.Str())
		}
	}
}

func TestPickProfileSpreadsAcrossRealFleet(t *testing.T) {
	fleet := map[string]int{
		"cyberghost": 7, "expressvpn": 8, "mullvad": 5, "nordvpn": 6, "ovpn": 7,
		"pia": 5, "purevpn": 9, "surfshark": 10, "tunnelbear": 8, "veepn": 5, "windscribe": 11,
	}
	used := map[string]bool{}
	for prov, n := range fleet {
		for i := 0; i < n; i++ {
			id := "tundler-tunnel-" + prov + "-" + itoa(i)
			p := PickProfile(id)
			used[p.Str()] = true
		}
	}
	if len(used) != ProfileCount() {
		t.Fatalf("real fleet used %d/%d profiles — rotation narrower than the pool", len(used), ProfileCount())
	}
}

func TestProfilesAreRealPresets(t *testing.T) {
	if ProfileCount() < 3 {
		t.Fatalf("want >=3 rotation profiles, got %d", ProfileCount())
	}
	for _, p := range browserProfiles {
		if p == (utls.ClientHelloID{}) || p.Str() == "" {
			t.Fatalf("empty/zero ClientHelloID in rotation set")
		}
	}
}
