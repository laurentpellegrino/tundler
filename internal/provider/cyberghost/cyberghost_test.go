package cyberghost

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

const (
	syntheticCert = "-----BEGIN CERTIFICATE-----\nc3ludGhldGljLWNlcnQ=\n-----END CERTIFICATE-----"
	syntheticKey  = "-----BEGIN TEST KEY-----\nc3ludGhldGljLWtleQ==\n-----END TEST KEY-----"
)

func TestBuildConfig(t *testing.T) {
	server := &cyberghostServer{Country: "Latvia", Hostname: "87-1-lv.cg-dialup.net"}
	cfg, err := buildOpenVPNConfig(server, syntheticCert+"\n", syntheticKey, "/run/cyberghost/openvpn-1/management.sock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"remote 87-1-lv.cg-dialup.net 443",
		"dev tun-cyberghost\ndev-type tun\n",
		"management \"/run/cyberghost/openvpn-1/management.sock\" unix\n",
		"management-query-passwords\n", "auth-user-pass\n", "auth-nocache\n",
		"tun-mtu 1320\n", "mssfix 1280\n", "connect-retry-max 1\n",
		"auth SHA256", "data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC",
		"<ca>\n-----BEGIN CERTIFICATE-----",
		"<cert>\n" + syntheticCert + "\n</cert>\n",
		"<key>\n" + syntheticKey + "\n</key>\n",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q", want)
		}
	}
	if strings.Contains(cfg, "auth-user-pass /") {
		t.Error("the password must come over the management socket, not from a file")
	}
	if _, err := buildOpenVPNConfig(server, syntheticCert, syntheticKey, "/bad\"quote.sock"); err == nil {
		t.Error("a socket path that breaks quoting must be rejected")
	}
	if _, err := buildOpenVPNConfig(server, syntheticCert+"\n</cert>\nup /bin/sh", syntheticKey, "/run/cyberghost/s.sock"); err == nil {
		t.Error("a certificate that closes its block must be rejected")
	}
	if _, err := buildOpenVPNConfig(server, syntheticCert, " \n", "/run/cyberghost/s.sock"); err == nil {
		t.Error("an empty key must be rejected")
	}
}

// withServer serves a one-server catalog, this pod's device credential
// and a stubbed openvpn start, so Connect never starts the openvpn
// installed on a desktop.
func withServer(t *testing.T, start func(context.Context, ovpn.Options, func(string) ([]byte, error)) (*ovpn.Tunnel, error)) {
	t.Helper()
	t.Setenv("TUNDLER_ACCOUNTS_DIR", t.TempDir())
	t.Setenv("TUNDLER_ACCOUNTS", "")
	t.Setenv("TUNDLER_ACCOUNT_CERTIFICATE", syntheticCert)
	t.Setenv("TUNDLER_ACCOUNT_KEY", syntheticKey)
	t.Setenv("TUNDLER_ACCOUNT_USERNAME", "user")
	t.Setenv("TUNDLER_ACCOUNT_PASSWORD", "synthetic-device-secret")
	accounts.Reset()
	serverCacheMu.Lock()
	prevCache := serverCache
	serverCache = []cyberghostServer{{Country: "Latvia", City: "Riga", Hostname: "87-1-lv.cg-dialup.net"}}
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
		if cfg, err = render("/run/cyberghost/openvpn-1/management.sock"); err != nil {
			return nil, err
		}
		return nil, ovpn.ErrAuthFailed
	})
	st := CyberGhost{}.Connect(context.Background(), "Latvia")
	if st.Connected || !st.AuthFailed || st.Location != "Latvia" {
		t.Fatalf("status = %+v, want AuthFailed at Latvia", st)
	}
	if opts.User != "user" || opts.Pass != "synthetic-device-secret" {
		t.Fatal("the credentials must be handed to the management exchange")
	}
	if strings.Contains(string(cfg), "synthetic-device-secret") {
		t.Fatal("the password must not be written into the config")
	}
	if !strings.Contains(string(cfg), syntheticCert) || !strings.Contains(string(cfg), syntheticKey) {
		t.Fatal("this pod's device certificate and key must be inline in the config")
	}
}

func TestConnectReportsOtherFailuresAsPlainFailures(t *testing.T) {
	withServer(t, func(context.Context, ovpn.Options, func(string) ([]byte, error)) (*ovpn.Tunnel, error) {
		return nil, errors.New("CyberGhost OpenVPN connection timed out")
	})
	if st := (CyberGhost{}).Connect(context.Background(), "Latvia"); st.Connected || st.AuthFailed {
		t.Fatalf("status = %+v, want a plain failure", st)
	}
}

func TestActiveLocationRoundTripAndDisconnect(t *testing.T) {
	withServer(t, nil)
	if got := (CyberGhost{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
	owned := exec.Command("sleep", "30")
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := ovpn.NewForTest(owned)
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: cyberghostServer{Country: "Latvia", City: "Riga", Hostname: "87-1-lv.cg-dialup.net"}, location: "Latvia"}
	activeMu.Unlock()
	if got := (CyberGhost{}).ActiveLocation(context.Background()); got != "Latvia" {
		t.Fatalf("ActiveLocation = %q, want Latvia", got)
	}
	if got := activeRegion(); got != "Latvia - Riga" {
		t.Fatalf("activeRegion = %q, want Latvia - Riga", got)
	}
	if err := (CyberGhost{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (CyberGhost{}).ActiveLocation(context.Background()) != "" || activeRegion() != "" {
		t.Fatal("Disconnect must clear the active connection")
	}
	select {
	case <-tunnel.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect left the owned process running")
	}
}
