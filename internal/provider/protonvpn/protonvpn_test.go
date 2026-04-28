package protonvpn

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func resetTestState(t *testing.T) {
	t.Helper()
	serverCacheMu.Lock()
	serverCache = nil
	serverCacheTime = time.Time{}
	activeServer = nil
	loggedIn = false
	serverCacheMu.Unlock()
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
}

func writeServersFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "servers.json")
	data := `{
  "protonvpn": {
    "servers": [
      {
        "vpn": "openvpn",
        "country": "France",
        "region": "Europe",
        "city": "Paris",
        "server_name": "FR#1",
        "hostname": "fr-001.protonvpn.net",
        "tcp": true,
        "udp": true,
        "ips": ["1.2.3.4"]
      },
      {
        "vpn": "openvpn",
        "country": "Germany",
        "region": "Europe",
        "city": "Berlin",
        "server_name": "DE#1",
        "hostname": "de-001.protonvpn.net",
        "tcp": true,
        "udp": false,
        "ips": ["5.6.7.8"]
      },
      {
        "vpn": "wireguard",
        "country": "France",
        "hostname": "fr-wg.protonvpn.net",
        "tcp": true,
        "udp": true,
        "ips": ["9.9.9.9"]
      }
    ]
  }
}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("write test servers file: %v", err)
	}
	return path
}

func TestLoginRequiresOpenVPNCredentials(t *testing.T) {
	resetTestState(t)
	t.Setenv("PROTON_SERVERS_FILE", writeServersFile(t))
	t.Setenv("PROTON_OPENVPN_USERNAME", "")
	t.Setenv("PROTON_OPENVPN_PASSWORD", "")

	err := ProtonVPN{}.Login(context.Background())
	if err == nil {
		t.Fatal("expected missing credentials error")
	}
	if !strings.Contains(err.Error(), "PROTON_OPENVPN_USERNAME") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoginLoadsOpenVPNServerMetadata(t *testing.T) {
	resetTestState(t)
	t.Setenv("PROTON_SERVERS_FILE", writeServersFile(t))
	t.Setenv("PROTON_OPENVPN_USERNAME", "user")
	t.Setenv("PROTON_OPENVPN_PASSWORD", "pass")
	t.Setenv("PROTON_OPENVPN_PROTOCOL", "udp")

	provider := ProtonVPN{}
	if err := provider.Login(context.Background()); err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if !provider.LoggedIn(context.Background()) {
		t.Fatal("expected provider to be logged in")
	}

	got := provider.Locations(context.Background())
	want := []string{"France"}
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected locations: got %v want %v", got, want)
	}
}

func TestFetchServersHonorsProtocol(t *testing.T) {
	resetTestState(t)
	t.Setenv("PROTON_SERVERS_FILE", writeServersFile(t))
	t.Setenv("PROTON_OPENVPN_PROTOCOL", "tcp")

	servers, err := fetchServers(context.Background())
	if err != nil {
		t.Fatalf("fetchServers returned error: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("unexpected server count: got %d want 2", len(servers))
	}

	matches := findServers(servers, "Berlin")
	if len(matches) != 1 || matches[0].Country != "Germany" {
		t.Fatalf("unexpected Berlin matches: %#v", matches)
	}
}

func TestBuildOpenVPNConfig(t *testing.T) {
	resetTestState(t)
	t.Setenv("PROTON_OPENVPN_PROTOCOL", "tcp")

	config := buildOpenVPNConfig(&protonServer{
		Hostname: "fr-001.protonvpn.net",
		IPs:      []string{"1.2.3.4", "1.2.3.5"},
	}, "/tmp/proton-auth.txt")

	for _, want := range []string{
		"proto tcp",
		"remote 1.2.3.4 443",
		"remote 1.2.3.5 443",
		"auth-user-pass /tmp/proton-auth.txt",
		"data-ciphers AES-256-GCM:AES-128-GCM",
		"<ca>",
		"<tls-crypt>",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("generated config missing %q:\n%s", want, config)
		}
	}
	if strings.Contains(config, "fast-io") {
		t.Fatalf("tcp config should not include udp-only fast-io:\n%s", config)
	}
}

// TestActiveLocationRoundTrip pins the contract that ActiveLocation
// returns the verbatim string passed to Connect, so a value pulled
// from Locations() (the candidate pool the manager picks from) and
// stamped onto Status.Location can be matched byte-for-byte against a
// config block/allow entry.
func TestActiveLocationRoundTrip(t *testing.T) {
	resetTestState(t)
	activeServer = &protonServer{Country: "France", City: "Paris"}
	activeMu.Lock()
	activeLocation = "France"
	activeMu.Unlock()

	if got := (ProtonVPN{}).ActiveLocation(context.Background()); got != "France" {
		t.Fatalf("ActiveLocation = %q, want %q", got, "France")
	}
}

func TestActiveLocationEmptyWhenDisconnected(t *testing.T) {
	resetTestState(t)
	// activeServer is nil → not connected → ActiveLocation must not
	// surface a stale value, even if activeLocation happens to be set.
	activeMu.Lock()
	activeLocation = "France"
	activeMu.Unlock()

	if got := (ProtonVPN{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
}

func TestDisconnectClearsActiveLocation(t *testing.T) {
	resetTestState(t)
	activeServer = &protonServer{Country: "France"}
	activeMu.Lock()
	activeLocation = "France"
	activeMu.Unlock()

	// Disconnect calls `pkill openvpn`, which is fine even when openvpn
	// isn't running (RunCmd swallows the non-zero exit). The state we
	// care about — activeServer/activeLocation — is cleared
	// unconditionally on the way out.
	if err := (ProtonVPN{}).Disconnect(context.Background()); err != nil {
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
