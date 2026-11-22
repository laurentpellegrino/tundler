package norton

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	ovpnrun "github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

var marseille = Server{IP: "138.199.14.130", Country: "FR", City: "Marseille", LocationKey: "FR-B8-MARSEILLE"}

func TestBuildConfig(t *testing.T) {
	cfg, err := buildOpenVPNConfig(&marseille, "/run/norton/openvpn-1/management.sock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"remote 138.199.14.130 443 tcp\n",
		"dev tun-norton\ndev-type tun\n",
		"management \"/run/norton/openvpn-1/management.sock\" unix\n",
		"management-query-passwords\n", "auth-user-pass\n", "auth-nocache\n",
		"tun-mtu 1320\n", "mssfix 1280\n", "connect-retry-max 1\n",
		"cipher AES-256-GCM\n", "data-ciphers AES-256-GCM\n", "remote-cert-tls server\n",
		"route 0.0.0.0 0.0.0.0\n", "allow-recursive-routing\n",
		"<ca>\n-----BEGIN CERTIFICATE-----",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q", want)
		}
	}
	if strings.Contains(cfg, "auth-user-pass /") {
		t.Error("the password must come over the management socket, not from a file")
	}
	if _, err := buildOpenVPNConfig(&marseille, "/bad\"quote.sock"); err == nil {
		t.Error("a socket path that breaks quoting must be rejected")
	}
}

func TestEmbeddedServersParse(t *testing.T) {
	servers, err := loadServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) == 0 {
		t.Fatal("embedded server snapshot is empty")
	}
	for _, s := range servers {
		if s.IP == "" {
			t.Errorf("server has no IP: %+v", s)
		}
	}
}

// withServer serves a one-server pool, a per-device credential and a stubbed
// openvpn start, so Connect never reads the embedded list or starts the
// openvpn installed on a desktop.
func withServer(t *testing.T, start func(context.Context, ovpnrun.Options, func(string) ([]byte, error)) (*ovpnrun.Tunnel, error)) {
	t.Helper()
	t.Setenv("TUNDLER_ACCOUNTS_DIR", t.TempDir())
	t.Setenv("TUNDLER_ACCOUNTS", "")
	t.Setenv("TUNDLER_ACCOUNT_USERNAME", "U1.tenant.nlk401.deadbeef")
	t.Setenv("TUNDLER_ACCOUNT_PASSWORD", "synthetic-device-secret")
	accounts.Reset()
	serverCacheMu.Lock()
	prevCache := serverCache
	serverCache = []Server{marseille}
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
		accounts.Reset()
	})
}

func TestConnectReportsAServerRefusingTheCredentials(t *testing.T) {
	var (
		opts ovpnrun.Options
		cfg  []byte
	)
	withServer(t, func(_ context.Context, o ovpnrun.Options, render func(string) ([]byte, error)) (*ovpnrun.Tunnel, error) {
		opts = o
		var err error
		if cfg, err = render("/run/norton/openvpn-1/management.sock"); err != nil {
			return nil, err
		}
		return nil, ovpnrun.ErrAuthFailed
	})
	st := Norton{}.Connect(context.Background(), "FR")
	if st.Connected || !st.AuthFailed || st.Location != "FR" {
		t.Fatalf("status = %+v, want AuthFailed at FR", st)
	}
	if opts.User != "U1.tenant.nlk401.deadbeef" || opts.Pass != "synthetic-device-secret" {
		t.Fatal("the credentials must be handed to the management exchange")
	}
	if strings.Contains(string(cfg), "synthetic-device-secret") {
		t.Fatal("the password must not be written into the config")
	}
}

func TestConnectReportsOtherFailuresAsPlainFailures(t *testing.T) {
	withServer(t, func(context.Context, ovpnrun.Options, func(string) ([]byte, error)) (*ovpnrun.Tunnel, error) {
		return nil, errors.New("norton OpenVPN connection timed out")
	})
	if st := (Norton{}).Connect(context.Background(), "FR"); st.Connected || st.AuthFailed {
		t.Fatalf("status = %+v, want a plain failure", st)
	}
}

func TestActiveLocationRoundTripAndDisconnect(t *testing.T) {
	withServer(t, nil)
	if got := (Norton{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
	owned := exec.Command("sleep", "30")
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := ovpnrun.NewForTest(owned)
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: marseille, location: "FR"}
	activeMu.Unlock()
	if got := (Norton{}).ActiveLocation(context.Background()); got != "FR" {
		t.Fatalf("ActiveLocation = %q, want FR", got)
	}
	if got := activeRegion(); got != "FR - Marseille" {
		t.Fatalf("activeRegion = %q, want FR - Marseille", got)
	}
	if err := (Norton{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (Norton{}).ActiveLocation(context.Background()) != "" || activeRegion() != "" {
		t.Fatal("Disconnect must clear the active connection")
	}
	select {
	case <-tunnel.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect left the owned process running")
	}
}
