package protonvpn

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

const testServersJSON = `{
  "protonvpn": {
    "servers": [
      {"vpn": "openvpn", "country": "France", "region": "Europe", "city": "Paris", "server_name": "FR#1",
       "hostname": "fr-001.protonvpn.net", "tcp": true, "udp": true, "ips": ["1.2.3.4"], "features": 12, "tier": 2},
      {"vpn": "openvpn", "country": "Germany", "region": "Europe", "city": "Berlin", "server_name": "DE#1",
       "hostname": "de-001.protonvpn.net", "tcp": true, "udp": false, "ips": ["5.6.7.8"], "features": 0, "tier": 2},
      {"vpn": "openvpn", "country": "Iceland", "region": "Europe", "city": "Reykjavik", "server_name": "CH-IS#1",
       "hostname": "ch-is-001.protonvpn.net", "tcp": true, "udp": true, "ips": ["9.9.9.9"], "features": 1, "tier": 2},
      {"vpn": "wireguard", "country": "France", "hostname": "fr-wg.protonvpn.net", "tcp": true, "udp": true, "ips": ["9.9.9.10"]}
    ]
  }
}`

// resetTestState clears the parsed-catalog memo so the next
// fetchServers re-parses embeddedServers, and clears the connection
// state between tests.
func resetTestState(t *testing.T) {
	t.Helper()
	serverCacheMu.Lock()
	serverCache = nil
	serverCacheOK = false
	serverCacheErr = nil
	loggedIn = false
	serverCacheMu.Unlock()
	activeMu.Lock()
	current = nil
	activeMu.Unlock()
}

// useTestServers stuffs the embedded-catalog package var with a
// deterministic fixture so tests never read /etc/protonvpn/servers.json.
func useTestServers(t *testing.T) {
	t.Helper()
	original := embeddedServers
	embeddedServers = []byte(testServersJSON)
	t.Cleanup(func() { embeddedServers = original })
}

func TestLoginRequiresOpenVPNCredentials(t *testing.T) {
	resetTestState(t)
	useTestServers(t)
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
	useTestServers(t)
	t.Setenv("PROTON_OPENVPN_USERNAME", "user")
	t.Setenv("PROTON_OPENVPN_PASSWORD", "pass")
	t.Setenv("PROTON_OPENVPN_PROTOCOL", "udp")
	t.Setenv("PROTON_FEATURE_FILTER", "")
	p := ProtonVPN{}
	if err := p.Login(context.Background()); err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if !p.LoggedIn(context.Background()) {
		t.Fatal("expected provider to be logged in")
	}
	got := p.Locations(context.Background())
	if want := []string{"France", "Iceland"}; !slices.Equal(got, want) {
		t.Fatalf("unexpected locations: got %v want %v", got, want)
	}
}

func TestFetchServersHonorsProtocolAndFeatureFilter(t *testing.T) {
	resetTestState(t)
	useTestServers(t)
	t.Setenv("PROTON_OPENVPN_PROTOCOL", "tcp")
	t.Setenv("PROTON_FEATURE_FILTER", "")
	servers, err := fetchServers(context.Background())
	if err != nil {
		t.Fatalf("fetchServers returned error: %v", err)
	}
	if len(servers) != 3 {
		t.Fatalf("unexpected server count: got %d want 3", len(servers))
	}
	if matches := findServers(servers, "Berlin"); len(matches) != 1 || matches[0].Country != "Germany" {
		t.Fatalf("unexpected Berlin matches: %#v", matches)
	}
	resetTestState(t)
	t.Setenv("PROTON_FEATURE_FILTER", "securecore")
	servers, err = fetchServers(context.Background())
	if err != nil || len(servers) != 1 || servers[0].ServerName != "CH-IS#1" {
		t.Fatalf("securecore filter: servers=%v err=%v", servers, err)
	}
}

func TestBuildOpenVPNConfigOwnsLifecycleAndKeepsProtonTransport(t *testing.T) {
	resetTestState(t)
	t.Setenv("PROTON_OPENVPN_PROTOCOL", "tcp")
	t.Setenv("PROTON_OPENVPN_PORT", "")
	raw, err := buildOpenVPNConfig(&protonServer{Hostname: "fr-001.protonvpn.net", IPs: []string{"1.2.3.4", "1.2.3.5"}}, "/run/protonvpn/openvpn-1/management.sock")
	if err != nil {
		t.Fatal(err)
	}
	config := string(raw)
	for _, want := range []string{
		"dev " + tunnelInterface + "\n", "proto tcp\n", "remote 1.2.3.4 443\n", "remote 1.2.3.5 443\n", "remote-random\n",
		"management \"/run/protonvpn/openvpn-1/management.sock\" unix\n", "management-query-passwords\n", "management-hold\n",
		"auth-user-pass\n", "auth-nocache\n", "connect-retry-max 1\n", "connect-timeout 15\n", "verb 0\n",
		"data-ciphers AES-256-GCM:AES-128-GCM\n", "remote-cert-tls server\n", "<ca>\n", "<tls-crypt>\n",
		"pull-filter ignore \"auth-token\"\n",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("generated config missing %q", want)
		}
	}
	for _, dropped := range []string{"fast-io", "auth-user-pass /", "auth-retry", "verb 3", "dev tun\n"} {
		if strings.Contains(config, dropped) {
			t.Errorf("generated config kept %q", dropped)
		}
	}
	t.Setenv("PROTON_OPENVPN_PROTOCOL", "udp")
	raw, err = buildOpenVPNConfig(&protonServer{Hostname: "fr-001.protonvpn.net"}, "/m.sock")
	if err != nil {
		t.Fatal(err)
	}
	if udp := string(raw); !strings.Contains(udp, "remote fr-001.protonvpn.net 1194\n") || !strings.Contains(udp, "fast-io") {
		t.Fatalf("udp config must fall back to the hostname on 1194 with fast-io:\n%s", udp)
	}
	if _, err := buildOpenVPNConfig(&protonServer{IPs: []string{"1.2.3.4\nremote evil 443"}}, "/m.sock"); err == nil {
		t.Fatal("a remote with embedded whitespace must be rejected")
	}
	if _, err := buildOpenVPNConfig(&protonServer{Hostname: "x"}, "/bad\"quote.sock"); err == nil {
		t.Fatal("a socket path that breaks quoting must be rejected")
	}
}

func TestActiveLocationRoundTripAndDisconnect(t *testing.T) {
	resetTestState(t)
	if got := (ProtonVPN{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
	owned := exec.Command("sleep", "30")
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := ovpn.NewForTest(owned)
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: &protonServer{Country: "France", City: "Paris"}, location: "France"}
	activeMu.Unlock()
	if got := (ProtonVPN{}).ActiveLocation(context.Background()); got != "France" {
		t.Fatalf("ActiveLocation = %q, want the verbatim Connect argument", got)
	}
	if got := activeRegion(); got != "France - Paris" {
		t.Fatalf("activeRegion = %q", got)
	}
	if err := (ProtonVPN{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (ProtonVPN{}).ActiveLocation(context.Background()) != "" || activeRegion() != "" {
		t.Fatal("Disconnect must clear the active connection")
	}
	select {
	case <-tunnel.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect left the owned process running")
	}
}
