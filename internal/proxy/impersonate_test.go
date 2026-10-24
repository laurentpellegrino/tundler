package proxy

import (
	"strings"
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

// A preset without a paired User-Agent would make the UA hint silently keep
// the client's (contradicting) UA. Each UA must also name the preset's own
// browser: a Firefox hello under a Chrome UA is the mismatch this exists to
// remove.
func TestEveryProfileHasAMatchingUserAgent(t *testing.T) {
	families := map[string]string{"Chrome": "Chrome/", "Firefox": "Firefox/", "Safari": "Version/", "Edge": "Edg/"}
	for _, p := range browserProfiles {
		ua := UserAgentFor(p)
		if ua == "" {
			t.Fatalf("preset %s has no User-Agent", p.Str())
		}
		marker, ok := families[p.Client]
		if !ok {
			t.Fatalf("preset %s: unknown browser family %q", p.Str(), p.Client)
		}
		if !strings.Contains(ua, marker) {
			t.Fatalf("preset %s: UA %q does not name its browser (want %q)", p.Str(), ua, marker)
		}
		if p.Client == "Chrome" && !strings.Contains(ua, "Chrome/"+p.Version+".") {
			t.Fatalf("preset %s: UA %q names a different Chrome version", p.Str(), ua)
		}
	}
	if UserAgentFor(utls.HelloGolang) != "" {
		t.Fatalf("a preset outside the rotation must have no UA")
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
