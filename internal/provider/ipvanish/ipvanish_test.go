package ipvanish

import (
	"context"
	"testing"
)

func resetActiveState(t *testing.T) {
	t.Helper()
	activeServer = nil
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
}

func TestParseFilename(t *testing.T) {
	tests := []struct {
		filename string
		want     ipvanishServer
		ok       bool
	}{
		{
			filename: "ipvanish-US-New-York-nyc-c28.ovpn",
			want: ipvanishServer{
				Country: "United States", CC: "US", City: "New York",
				Hostname: "nyc-c28.ipvanish.com",
				Filename: "ipvanish-US-New-York-nyc-c28.ovpn",
			},
			ok: true,
		},
		{
			filename: "ipvanish-UK-London-lon-b23.ovpn",
			want: ipvanishServer{
				Country: "United Kingdom", CC: "UK", City: "London",
				Hostname: "lon-b23.ipvanish.com",
				Filename: "ipvanish-UK-London-lon-b23.ovpn",
			},
			ok: true,
		},
		{
			filename: "ipvanish-AD-Andorra-la-Vella---Virtual-adv-c01.ovpn",
			want: ipvanishServer{
				Country: "Andorra", CC: "AD", City: "Andorra la Vella",
				Hostname: "adv-c01.ipvanish.com", Virtual: true,
				Filename: "ipvanish-AD-Andorra-la-Vella---Virtual-adv-c01.ovpn",
			},
			ok: true,
		},
		{
			// Server number with three digits.
			filename: "ipvanish-DE-Frankfurt-fra-a123.ovpn",
			want: ipvanishServer{
				Country: "Germany", CC: "DE", City: "Frankfurt",
				Hostname: "fra-a123.ipvanish.com",
				Filename: "ipvanish-DE-Frankfurt-fra-a123.ovpn",
			},
			ok: true,
		},
		{
			// Unknown CC falls back to the raw code.
			filename: "ipvanish-XX-Mystery-mys-a01.ovpn",
			want: ipvanishServer{
				Country: "XX", CC: "XX", City: "Mystery",
				Hostname: "mys-a01.ipvanish.com",
				Filename: "ipvanish-XX-Mystery-mys-a01.ovpn",
			},
			ok: true,
		},
		{filename: "not-an-ipvanish-config.ovpn", ok: false},
		{filename: "ipvanish-US-New-York.ovpn", ok: false},
	}

	for _, tc := range tests {
		got, ok := parseFilename(tc.filename)
		if ok != tc.ok {
			t.Errorf("parseFilename(%q) ok = %v, want %v", tc.filename, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if got != tc.want {
			t.Errorf("parseFilename(%q)\n got: %+v\nwant: %+v", tc.filename, got, tc.want)
		}
	}
}

// TestActiveLocationRoundTrip pins the contract that ActiveLocation returns
// the verbatim string passed to Connect, so a value pulled from Locations()
// and stamped onto Status.Location matches a config block/allow entry
// byte-for-byte.
func TestActiveLocationRoundTrip(t *testing.T) {
	resetActiveState(t)
	t.Cleanup(func() { resetActiveState(t) })

	activeServer = &ipvanishServer{Country: "United States", City: "New York"}
	activeMu.Lock()
	activeLocation = "United States"
	activeMu.Unlock()

	if got := (IPVanish{}).ActiveLocation(context.Background()); got != "United States" {
		t.Fatalf("ActiveLocation = %q, want %q", got, "United States")
	}
}

func TestActiveLocationEmptyWhenDisconnected(t *testing.T) {
	resetActiveState(t)
	t.Cleanup(func() { resetActiveState(t) })

	activeMu.Lock()
	activeLocation = "United States"
	activeMu.Unlock()

	if got := (IPVanish{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
}

func TestDisconnectClearsActiveLocation(t *testing.T) {
	resetActiveState(t)
	t.Cleanup(func() { resetActiveState(t) })

	activeServer = &ipvanishServer{Country: "United States"}
	activeMu.Lock()
	activeLocation = "United States"
	activeMu.Unlock()

	if err := (IPVanish{}).Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect error: %v", err)
	}
	if activeServer != nil {
		t.Fatalf("activeServer not cleared after Disconnect")
	}
	activeMu.RLock()
	got := activeLocation
	activeMu.RUnlock()
	if got != "" {
		t.Fatalf("activeLocation after Disconnect = %q, want empty", got)
	}
}
