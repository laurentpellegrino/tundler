package hidemyass

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetActiveState(t *testing.T) {
	t.Helper()
	activeServer = nil
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
	serverCacheMu.Lock()
	serverCache = nil
	serverCacheMu.Unlock()
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		path string
		want hmaServer
		ok   bool
	}{
		{
			path: "USA.NewYork.Manhattan_LOC1S12.UDP.ovpn",
			want: hmaServer{Country: "United States", CC: "US", Region: "New York", City: "Manhattan", Proto: "udp",
				Path: "USA.NewYork.Manhattan_LOC1S12.UDP.ovpn"},
			ok: true,
		},
		{
			path: "UnitedKingdom.London_LOC1S1.TCP.ovpn",
			want: hmaServer{Country: "United Kingdom", CC: "GB", City: "London", Proto: "tcp",
				Path: "UnitedKingdom.London_LOC1S1.TCP.ovpn"},
			ok: true,
		},
		{
			// Proto from the directory layout, no suffix.
			path: filepath.Join("UDP", "CzechRepublic.Prague.ovpn"),
			want: hmaServer{Country: "Czech Republic", CC: "CZ", City: "Prague", Proto: "udp",
				Path: filepath.Join("UDP", "CzechRepublic.Prague.ovpn")},
			ok: true,
		},
		{
			// Virtual-location marker on the city.
			path: "Netherlands.Amsterdam-VirtualUSA_LOC1S3.UDP.ovpn",
			want: hmaServer{Country: "Netherlands", CC: "NL", City: "Amsterdam", Proto: "udp", Virtual: true,
				Path: "Netherlands.Amsterdam-VirtualUSA_LOC1S3.UDP.ovpn"},
			ok: true,
		},
		{
			// City-less country profile.
			path: "Luxembourg_LOC1S4.UDP.ovpn",
			want: hmaServer{Country: "Luxembourg", CC: "LU", Proto: "udp", Path: "Luxembourg_LOC1S4.UDP.ovpn"},
			ok:   true,
		},
		{
			// Dotted city under a region.
			path: "USA.Missouri.St.Louis_LOC1S1.UDP.ovpn",
			want: hmaServer{Country: "United States", CC: "US", Region: "Missouri", City: "St.Louis", Proto: "udp",
				Path: "USA.Missouri.St.Louis_LOC1S1.UDP.ovpn"},
			ok: true,
		},
		{
			// Backtick apostrophe in HMA's spelling.
			path: "Coted`Ivoire.Yamoussoukro.UDP.ovpn",
			want: hmaServer{Country: "Ivory Coast", CC: "CI", City: "Yamoussoukro", Proto: "udp",
				Path: "Coted`Ivoire.Yamoussoukro.UDP.ovpn"},
			ok: true,
		},
		{
			// CamelCase country split into a canonical name.
			path: "UnitedArabEmirates.Dubai.UDP.ovpn",
			want: hmaServer{Country: "United Arab Emirates", CC: "AE", City: "Dubai", Proto: "udp",
				Path: "UnitedArabEmirates.Dubai.UDP.ovpn"},
			ok: true,
		},
		{
			// Unknown to geo: spaced-out spelling, no code, still connectable.
			path: "PitcairnIslands.Adamstown.UDP.ovpn",
			want: hmaServer{Country: "Pitcairn Islands", City: "Adamstown", Proto: "udp",
				Path: "PitcairnIslands.Adamstown.UDP.ovpn"},
			ok: true,
		},
		{path: "README.md", ok: false},
		{path: ".ovpn", ok: false},
	}

	for _, tc := range tests {
		got, ok := parsePath(tc.path)
		if ok != tc.ok {
			t.Errorf("parsePath(%q) ok = %v, want %v", tc.path, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if got != tc.want {
			t.Errorf("parsePath(%q)\n got: %+v\nwant: %+v", tc.path, got, tc.want)
		}
	}
}

func TestFindServersPrefersUDP(t *testing.T) {
	servers := []hmaServer{
		{Country: "Austria", CC: "AT", City: "Vienna", Proto: "tcp"},
		{Country: "Austria", CC: "AT", City: "Vienna", Proto: "udp"},
		{Country: "Germany", CC: "DE", City: "Berlin", Proto: "tcp"},
	}
	if got := findServers(servers, "austria"); len(got) != 1 || got[0].Proto != "udp" {
		t.Fatalf("findServers(austria) = %+v, want the single UDP profile", got)
	}
	if got := findServers(servers, "AT"); len(got) != 1 || got[0].Proto != "udp" {
		t.Fatalf("findServers(AT) = %+v, want the single UDP profile", got)
	}
	// TCP-only location still connectable.
	if got := findServers(servers, "Germany"); len(got) != 1 || got[0].Proto != "tcp" {
		t.Fatalf("findServers(Germany) = %+v, want the TCP profile", got)
	}
	if got := findServers(servers, "Mars"); len(got) != 0 {
		t.Fatalf("findServers(Mars) = %+v, want none", got)
	}
}

func TestRewriteProfile(t *testing.T) {
	raw := "client\nauth-user-pass\nns-cert-type server\ncipher AES-256-CBC\ncomp-lzo\nproto udp\nremote 1.2.3.4 53"
	got := rewriteProfile(raw, "/etc/hidemyass/openvpn/auth.txt")
	for _, want := range []string{
		"auth-user-pass /etc/hidemyass/openvpn/auth.txt\n",
		"remote-cert-tls server\n",
		"remote 1.2.3.4 53\n",
		"data-ciphers-fallback AES-256-CBC\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rewritten profile lacks %q:\n%s", want, got)
		}
	}
	for _, gone := range []string{"ns-cert-type", "cipher AES-256-CBC", "comp-lzo"} {
		if strings.Contains(got, gone) {
			t.Errorf("rewritten profile still carries %q:\n%s", gone, got)
		}
	}
}

func TestLocationsFromConfigDir(t *testing.T) {
	resetActiveState(t)
	t.Cleanup(func() { resetActiveState(t) })

	dir := t.TempDir()
	for _, rel := range []string{
		"USA.Texas.Dallas_LOC1S1.UDP.ovpn",
		"USA.Texas.Dallas_LOC1S2.UDP.ovpn",
		filepath.Join("TCP", "Germany.Frankfurt.ovpn"),
		"notes.txt",
	} {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("client\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HIDEMYASS_CONFIG_DIR", dir)

	got := (HideMyAss{}).Locations(context.Background())
	want := []string{"Germany", "United States"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Locations() = %v, want %v", got, want)
	}
}

// TestActiveLocationRoundTrip pins the contract that ActiveLocation
// returns the verbatim string passed to Connect.
func TestActiveLocationRoundTrip(t *testing.T) {
	resetActiveState(t)
	t.Cleanup(func() { resetActiveState(t) })

	activeServer = &hmaServer{Country: "United States", Region: "Texas", City: "Dallas"}
	activeMu.Lock()
	activeLocation = "United States"
	activeMu.Unlock()

	if got := (HideMyAss{}).ActiveLocation(context.Background()); got != "United States" {
		t.Fatalf("ActiveLocation = %q, want %q", got, "United States")
	}
	if got := activeRegion(); got != "United States - Texas - Dallas" {
		t.Fatalf("activeRegion = %q", got)
	}
}

func TestDisconnectClearsActiveLocation(t *testing.T) {
	resetActiveState(t)
	t.Cleanup(func() { resetActiveState(t) })

	activeServer = &hmaServer{Country: "United States"}
	activeMu.Lock()
	activeLocation = "United States"
	activeMu.Unlock()

	if err := (HideMyAss{}).Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect error: %v", err)
	}
	if activeServer != nil {
		t.Fatalf("activeServer not cleared after Disconnect")
	}
	if got := (HideMyAss{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation after Disconnect = %q, want empty", got)
	}
}

func TestSpaceCamel(t *testing.T) {
	cases := map[string]string{
		"USA":                          "USA",
		"LosAngeles":                   "Los Angeles",
		"WashingtonDC":                 "Washington DC",
		"AntiguaandBarbuda":            "Antigua and Barbuda",
		"RepublicoftheCongo":           "Republic of the Congo",
		"SaintVincentandtheGrenadines": "Saint Vincent and the Grenadines",
		"Poland":                       "Poland",
		"Thailand":                     "Thailand",
		"Netherlands":                  "Netherlands",
	}
	for in, want := range cases {
		if got := spaceCamel(in); got != want {
			t.Errorf("spaceCamel(%q) = %q, want %q", in, got, want)
		}
	}
	if country, cc := resolveCountry("TrinidadandTobago"); country != "Trinidad and Tobago" || cc != "TT" {
		t.Errorf("resolveCountry(TrinidadandTobago) = %q/%q", country, cc)
	}
	if country, cc := resolveCountry("Brasil"); country != "Brazil" || cc != "BR" {
		t.Errorf("resolveCountry(Brasil) = %q/%q", country, cc)
	}
}
