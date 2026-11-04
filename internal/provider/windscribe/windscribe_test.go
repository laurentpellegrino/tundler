package windscribe

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

func TestBuildConfig(t *testing.T) {
	cfg, err := buildOpenVPNConfig(node{Hostname: "ber-449.whiskergalaxy.com"}, "/run/windscribe/openvpn-1/management.sock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"remote ber-449.whiskergalaxy.com 443",
		"dev tun-windscribe\ndev-type tun\n",
		"management \"/run/windscribe/openvpn-1/management.sock\" unix\n",
		"management-query-passwords\n", "auth-user-pass\n", "auth-nocache\n",
		"cipher AES-256-GCM", "auth SHA512", "key-direction 1",
		"-----BEGIN CERTIFICATE-----", "-----BEGIN OpenVPN Static key V1-----",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q", want)
		}
	}
	if strings.Contains(cfg, "auth-user-pass /") {
		t.Error("the password must come over the management socket, not from a file")
	}
	if _, err := buildOpenVPNConfig(node{Hostname: "x"}, "/bad\"quote.sock"); err == nil {
		t.Error("a socket path that breaks quoting must be rejected")
	}
}

func TestEmbeddedFallbackParses(t *testing.T) {
	var sl serverList
	if err := json.Unmarshal(embeddedServers, &sl); err != nil {
		t.Fatalf("embedded servers.json invalid: %v", err)
	}
	withNodes := 0
	for _, l := range sl.Data {
		if len(l.Nodes) > 0 {
			withNodes++
		}
	}
	if withNodes < 20 {
		t.Errorf("embedded fallback has only %d locations with nodes (<20)", withNodes)
	}
	t.Logf("embedded fallback: %d locations, %d with nodes", len(sl.Data), withNodes)
}

// withNode serves a one-location catalog, credentials and a stubbed
// openvpn start, so Connect never fetches the live list or starts the
// openvpn installed on a desktop.
func withNode(t *testing.T, start func(context.Context, ovpn.Options, func(string) ([]byte, error)) (*ovpn.Tunnel, error)) {
	t.Helper()
	t.Setenv("WINDSCRIBE_USERNAME", "user")
	t.Setenv("WINDSCRIBE_PASSWORD", "pass")
	serverCacheMu.Lock()
	prevCache := serverCache
	serverCache = []location{{Name: "Latvia", Nodes: []node{{Hostname: "lv-014.whiskergalaxy.com"}}}}
	serverCacheMu.Unlock()
	prevStart := startTunnel
	startTunnel = start
	t.Cleanup(func() {
		serverCacheMu.Lock()
		serverCache = prevCache
		serverCacheMu.Unlock()
		startTunnel = prevStart
		activeMu.Lock()
		current = nil
		activeMu.Unlock()
	})
}

func TestConnectReportsANodeRefusingTheCredentials(t *testing.T) {
	var opts ovpn.Options
	withNode(t, func(_ context.Context, o ovpn.Options, _ func(string) ([]byte, error)) (*ovpn.Tunnel, error) {
		opts = o
		return nil, ovpn.ErrAuthFailed
	})
	st := Windscribe{}.Connect(context.Background(), "Latvia")
	if st.Connected || !st.AuthFailed || st.Location != "Latvia" {
		t.Fatalf("status = %+v, want AuthFailed at Latvia", st)
	}
	if opts.User != "user" || opts.Pass != "pass" {
		t.Fatal("the credentials must be handed to the management exchange")
	}
}

func TestConnectReportsOtherFailuresAsPlainFailures(t *testing.T) {
	withNode(t, func(context.Context, ovpn.Options, func(string) ([]byte, error)) (*ovpn.Tunnel, error) {
		return nil, errors.New("Windscribe OpenVPN connection timed out")
	})
	if st := (Windscribe{}).Connect(context.Background(), "Latvia"); st.Connected || st.AuthFailed {
		t.Fatalf("status = %+v, want a plain failure", st)
	}
}

func TestActiveLocationRoundTripAndDisconnect(t *testing.T) {
	withNode(t, nil)
	if got := (Windscribe{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
	owned := exec.Command("sleep", "30")
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := ovpn.NewForTest(owned)
	activeMu.Lock()
	current = &active{tunnel: tunnel, location: "Latvia", hostname: "lv-014.whiskergalaxy.com"}
	activeMu.Unlock()
	if got := (Windscribe{}).ActiveLocation(context.Background()); got != "Latvia" {
		t.Fatalf("ActiveLocation = %q, want Latvia", got)
	}
	if err := (Windscribe{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (Windscribe{}).ActiveLocation(context.Background()) != "" {
		t.Fatal("Disconnect must clear the active connection")
	}
	select {
	case <-tunnel.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect left the owned process running")
	}
}
