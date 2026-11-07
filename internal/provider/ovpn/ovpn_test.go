package ovpn

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

var stockholm = Server{Slug: "stockholm", City: "Stockholm", Country: "SE"}

func TestBuildConfig(t *testing.T) {
	cfg, err := buildOpenVPNConfig(&stockholm, "/run/ovpn/openvpn-1/management.sock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"remote pool-1.prd.se.stockholm.ovpn.com 1194\n",
		"remote pool-1.prd.se.stockholm.ovpn.com 1195\n",
		"dev tun-ovpn\ndev-type tun\n",
		"management \"/run/ovpn/openvpn-1/management.sock\" unix\n",
		"management-query-passwords\n", "auth-user-pass\n", "auth-nocache\n",
		"tun-mtu 1320\n", "mssfix 1280\n", "connect-retry-max 1\n",
		"cipher CHACHA20-POLY1305", "key-direction 1",
		"<ca>\n-----BEGIN CERTIFICATE-----", "<tls-auth>\n-----BEGIN OpenVPN Static key V1-----",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q", want)
		}
	}
	if strings.Contains(cfg, "auth-user-pass /") {
		t.Error("the password must come over the management socket, not from a file")
	}
	if _, err := buildOpenVPNConfig(&stockholm, "/bad\"quote.sock"); err == nil {
		t.Error("a socket path that breaks quoting must be rejected")
	}
}

// withServer serves a one-datacenter catalog, the shared credential and
// a stubbed openvpn start, so Connect never reads the baked list or
// starts the openvpn installed on a desktop.
func withServer(t *testing.T, start func(context.Context, ovpnrun.Options, func(string) ([]byte, error)) (*ovpnrun.Tunnel, error)) {
	t.Helper()
	t.Setenv("TUNDLER_ACCOUNTS_DIR", t.TempDir())
	t.Setenv("TUNDLER_ACCOUNTS", "")
	t.Setenv("TUNDLER_ACCOUNT_USERNAME", "user")
	t.Setenv("TUNDLER_ACCOUNT_PASSWORD", "synthetic-shared-secret")
	accounts.Reset()
	serverCacheMu.Lock()
	prevCache := serverCache
	serverCache = []Server{stockholm}
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
		if cfg, err = render("/run/ovpn/openvpn-1/management.sock"); err != nil {
			return nil, err
		}
		return nil, ovpnrun.ErrAuthFailed
	})
	st := OVPN{}.Connect(context.Background(), "SE")
	if st.Connected || !st.AuthFailed || st.Location != "SE" {
		t.Fatalf("status = %+v, want AuthFailed at SE", st)
	}
	if opts.User != "user" || opts.Pass != "synthetic-shared-secret" {
		t.Fatal("the credentials must be handed to the management exchange")
	}
	if strings.Contains(string(cfg), "synthetic-shared-secret") {
		t.Fatal("the password must not be written into the config")
	}
}

func TestConnectReportsOtherFailuresAsPlainFailures(t *testing.T) {
	withServer(t, func(context.Context, ovpnrun.Options, func(string) ([]byte, error)) (*ovpnrun.Tunnel, error) {
		return nil, errors.New("OVPN OpenVPN connection timed out")
	})
	if st := (OVPN{}).Connect(context.Background(), "SE"); st.Connected || st.AuthFailed {
		t.Fatalf("status = %+v, want a plain failure", st)
	}
}

func TestActiveLocationRoundTripAndDisconnect(t *testing.T) {
	withServer(t, nil)
	if got := (OVPN{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
	owned := exec.Command("sleep", "30")
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := ovpnrun.NewForTest(owned)
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: stockholm, location: "SE"}
	activeMu.Unlock()
	if got := (OVPN{}).ActiveLocation(context.Background()); got != "SE" {
		t.Fatalf("ActiveLocation = %q, want SE", got)
	}
	if got := activeRegion(); got != "SE - Stockholm" {
		t.Fatalf("activeRegion = %q, want SE - Stockholm", got)
	}
	if err := (OVPN{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (OVPN{}).ActiveLocation(context.Background()) != "" || activeRegion() != "" {
		t.Fatal("Disconnect must clear the active connection")
	}
	select {
	case <-tunnel.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect left the owned process running")
	}
}
