package proxy

import (
	"net"
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

// An operator override must reach every rotation preset by its printed name
// (case-insensitively, since env values get typed by hand), plus the stock
// Go hello, and must refuse anything else rather than silently falling back.
func TestProfileByName(t *testing.T) {
	for _, p := range browserProfiles {
		got, ok := ProfileByName(strings.ToLower(p.Str()))
		if !ok || got.Str() != p.Str() {
			t.Fatalf("ProfileByName(%q) = %v,%v", p.Str(), got.Str(), ok)
		}
	}
	if got, ok := ProfileByName("golang"); !ok || got != utls.HelloGolang {
		t.Fatalf("ProfileByName(golang) = %v,%v", got.Str(), ok)
	}
	if _, ok := ProfileByName("netscape-4"); ok {
		t.Fatalf("unknown preset must not resolve")
	}
	if UserAgentFor(utls.HelloGolang) != "" {
		t.Fatalf("golang has no browser UA: the client's UA must be kept")
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

func TestProfileByName_NonBrowserPresets(t *testing.T) {
	for name, want := range map[string]utls.ClientHelloID{
		"golang":     utls.HelloGolang,
		"RANDOMIZED": utls.HelloRandomizedALPN,
		"okhttp":     utls.HelloAndroid_11_OkHttp,
	} {
		got, ok := ProfileByName(name)
		if !ok || got != want {
			t.Fatalf("ProfileByName(%q) = %v, %v; want %v", name, got, ok, want)
		}
		if ua := UserAgentFor(got); ua != "" {
			t.Fatalf("non-browser preset %q must keep the client's User-Agent, got %q", name, ua)
		}
	}
}

func TestOpenSSL3Spec_AppliesAndMatchesCapture(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	uconn := utls.UClient(c, &utls.Config{ServerName: "example.com"}, utls.HelloCustom)
	if err := uconn.ApplyPreset(openSSL3Spec()); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	// JA4 t13d3112h2: 31 cipher suites, 12 extensions, ALPN h2 first.
	if n := len(uconn.HandshakeState.Hello.CipherSuites); n != 31 {
		t.Fatalf("cipher suites = %d, want 31", n)
	}
	if n := len(uconn.Extensions); n != 12 {
		t.Fatalf("extensions = %d, want 12", n)
	}
	if got := uconn.HandshakeState.Hello.AlpnProtocols; len(got) != 2 || got[0] != "h2" {
		t.Fatalf("alpn = %v, want [h2 http/1.1]", got)
	}
	if id, ok := ProfileByName("OpenSSL3"); !ok || id != HelloOpenSSL3 || UserAgentFor(id) != "" {
		t.Fatalf("ProfileByName(openssl3) = %v, %v", id, ok)
	}
}
