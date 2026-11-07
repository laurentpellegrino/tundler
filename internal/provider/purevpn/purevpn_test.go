package purevpn

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	"github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

func TestBuildConfig(t *testing.T) {
	cfg, err := buildOpenVPNConfig("de2", "/run/purevpn/openvpn-1/management.sock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"remote de2-auto-udp-qr.ptoserver.com 1194\n",
		"dev tun-purevpn\ndev-type tun\n",
		"management \"/run/purevpn/openvpn-1/management.sock\" unix\n",
		"management-query-passwords\n", "auth-user-pass\n", "auth-nocache\n",
		"tun-mtu 1320\n", "mssfix 1280\n", "connect-retry-max 1\n",
		"cipher AES-256-GCM", "key-direction 1",
		"<ca>\n-----BEGIN CERTIFICATE-----", "<tls-auth>\n-----BEGIN OpenVPN Static key V1-----",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q", want)
		}
	}
	if strings.Contains(cfg, "auth-user-pass /") {
		t.Error("the password must come over the management socket, not from a file")
	}
	if _, err := buildOpenVPNConfig("de2", "/bad\"quote.sock"); err == nil {
		t.Error("a socket path that breaks quoting must be rejected")
	}
}

// withServer serves a one-server catalog, the shared credential and a
// stubbed openvpn start, so Connect never reads the baked list or starts
// the openvpn installed on a desktop.
func withServer(t *testing.T, start func(context.Context, ovpn.Options, func(string) ([]byte, error)) (*ovpn.Tunnel, error)) {
	t.Helper()
	t.Setenv("TUNDLER_ACCOUNTS_DIR", t.TempDir())
	t.Setenv("TUNDLER_ACCOUNTS", "")
	t.Setenv("TUNDLER_ACCOUNT_USERNAME", "user")
	t.Setenv("TUNDLER_ACCOUNT_PASSWORD", "synthetic-shared-secret")
	accounts.Reset()
	serverCacheMu.Lock()
	prevCache := serverCache
	serverCache = []string{"de2"}
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
		opts ovpn.Options
		cfg  []byte
	)
	withServer(t, func(_ context.Context, o ovpn.Options, render func(string) ([]byte, error)) (*ovpn.Tunnel, error) {
		opts = o
		var err error
		if cfg, err = render("/run/purevpn/openvpn-1/management.sock"); err != nil {
			return nil, err
		}
		return nil, ovpn.ErrAuthFailed
	})
	st := PureVPN{}.Connect(context.Background(), "de")
	if st.Connected || !st.AuthFailed || st.Location != "de" {
		t.Fatalf("status = %+v, want AuthFailed at de", st)
	}
	if opts.User != "user" || opts.Pass != "synthetic-shared-secret" {
		t.Fatal("the credentials must be handed to the management exchange")
	}
	if strings.Contains(string(cfg), "synthetic-shared-secret") {
		t.Fatal("the password must not be written into the config")
	}
}

func TestConnectReportsOtherFailuresAsPlainFailures(t *testing.T) {
	withServer(t, func(context.Context, ovpn.Options, func(string) ([]byte, error)) (*ovpn.Tunnel, error) {
		return nil, errors.New("PureVPN OpenVPN connection timed out")
	})
	if st := (PureVPN{}).Connect(context.Background(), "de"); st.Connected || st.AuthFailed {
		t.Fatalf("status = %+v, want a plain failure", st)
	}
}

func TestActiveLocationRoundTripAndDisconnect(t *testing.T) {
	withServer(t, nil)
	if got := (PureVPN{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
	owned := exec.Command("sleep", "30")
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := ovpn.NewForTest(owned)
	activeMu.Lock()
	current = &active{tunnel: tunnel, slug: "de2", location: "de"}
	activeMu.Unlock()
	if got := (PureVPN{}).ActiveLocation(context.Background()); got != "de" {
		t.Fatalf("ActiveLocation = %q, want de", got)
	}
	if got := activeSlug(); got != "de2" {
		t.Fatalf("activeSlug = %q, want de2", got)
	}
	if err := (PureVPN{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (PureVPN{}).ActiveLocation(context.Background()) != "" || activeSlug() != "" {
		t.Fatal("Disconnect must clear the active connection")
	}
	select {
	case <-tunnel.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect left the owned process running")
	}
}
