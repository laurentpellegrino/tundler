package fastvpn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/shared/ovpn"
	"github.com/laurentpellegrino/tundler/internal/shared/warpproxy"
)

// sampleOVPN is the shape of a vendor TCP config (keys shortened).
const sampleOVPN = `client
dev tun
proto tcp
remote uio-c01.vpn.wlvpn.com 443
remote uio-c02.vpn.wlvpn.com 443
remote-random
resolv-retry infinite
nobind
persist-key
persist-tun
persist-remote-ip
<ca>
-----BEGIN CERTIFICATE-----
dev+notADirectiveInsideTheBlock
-----END CERTIFICATE-----
</ca>
verify-x509-name uio-c0 name-prefix
remote-cert-tls server
auth-user-pass
verb 3
auth SHA256
data-ciphers AES-256-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC
tls-cipher TLS-DHE-RSA-WITH-AES-256-CBC-SHA
`

func TestOpenVPNConfigKeepsTheVendorTransportAndOwnsTheLifecycle(t *testing.T) {
	cfg, err := openVPNConfig([]byte(sampleOVPN), "/run/fastvpn/openvpn-1/management.sock", false)
	if err != nil {
		t.Fatal(err)
	}
	text := string(cfg)
	for _, want := range []string{
		"remote uio-c01.vpn.wlvpn.com 443\n", "remote uio-c02.vpn.wlvpn.com 443\n", "remote-random\n",
		"verify-x509-name uio-c0 name-prefix\n", "tls-cipher TLS-DHE-RSA-WITH-AES-256-CBC-SHA\n", "persist-remote-ip\n",
		"dev+notADirectiveInsideTheBlock\n",
		"dev tun-fastvpn\ndev-type tun\n",
		"management \"/run/fastvpn/openvpn-1/management.sock\" unix\n", "management-query-passwords\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("config missing %q", want)
		}
	}
	if strings.Contains(text, "\ndev tun\n") {
		t.Error("the vendor dev line must be replaced by the fixed interface")
	}
	if strings.Count(text, "auth-user-pass") != 1 {
		t.Error("exactly one auth-user-pass (the management one) expected")
	}
	if strings.Contains(text, "socks-proxy") {
		t.Error("direct transport must not dial through the WARP proxy")
	}
	warp, err := openVPNConfig([]byte(sampleOVPN), "/run/fastvpn/openvpn-1/management.sock", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(warp), "socks-proxy "+warpproxy.Addr+"\n") {
		t.Error("warp transport must dial through the WARP proxy")
	}
	if _, err := openVPNConfig([]byte(sampleOVPN), "/bad\"quote.sock", false); err == nil {
		t.Error("a socket path that breaks quoting must be rejected")
	}
}

// withCity serves one baked city, credentials, the direct transport and
// a stubbed openvpn start, so Connect never reaches WARP or the openvpn
// installed on a desktop.
func withCity(t *testing.T, start func(context.Context, ovpn.Options, func(string) ([]byte, error)) (*ovpn.Tunnel, error)) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "NCVPN-EC-Quito - Virtual-UDP.ovpn"), []byte(sampleOVPN), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FASTVPN_CONFIG_DIR", dir)
	t.Setenv("FASTVPN_TRANSPORT", "direct")
	t.Setenv("FASTVPN_USERNAME", "user")
	t.Setenv("FASTVPN_PASSWORD", "pass")
	serverCacheMu.Lock()
	prevCache := serverCache
	serverCache = nil
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

func TestConnectReportsAnEdgeRefusingTheCredentials(t *testing.T) {
	var opts ovpn.Options
	var rendered []byte
	withCity(t, func(_ context.Context, o ovpn.Options, render func(string) ([]byte, error)) (*ovpn.Tunnel, error) {
		opts = o
		rendered, _ = render("/run/fastvpn/openvpn-1/management.sock")
		return nil, ovpn.ErrAuthFailed
	})
	st := FastVPN{}.Connect(context.Background(), "Ecuador")
	if st.Connected || !st.AuthFailed || st.Location != "Ecuador" {
		t.Fatalf("status = %+v, want AuthFailed at Ecuador", st)
	}
	if opts.User != "user" || opts.Pass != "pass" {
		t.Fatal("the credentials must be handed to the management exchange")
	}
	if !strings.Contains(string(rendered), "remote uio-c01.vpn.wlvpn.com 443") {
		t.Fatal("Connect must render the chosen city's vendor config")
	}
}

func TestConnectReportsOtherFailuresAsPlainFailures(t *testing.T) {
	withCity(t, func(context.Context, ovpn.Options, func(string) ([]byte, error)) (*ovpn.Tunnel, error) {
		return nil, errors.New("FastVPN OpenVPN connection timed out")
	})
	if st := (FastVPN{}).Connect(context.Background(), "Ecuador"); st.Connected || st.AuthFailed {
		t.Fatalf("status = %+v, want a plain failure", st)
	}
}

func TestConnectReportsAConnectTheProxyStopped(t *testing.T) {
	var opts ovpn.Options
	withCity(t, func(_ context.Context, o ovpn.Options, _ func(string) ([]byte, error)) (*ovpn.Tunnel, error) {
		opts = o
		return nil, fmt.Errorf("FastVPN OpenVPN gave up: %w", ovpn.ErrProxyFailed)
	})
	if st := (FastVPN{}).Connect(context.Background(), "Ecuador"); st.Connected || st.AuthFailed || !st.ProxyFailed {
		t.Fatalf("status = %+v, want ProxyFailed", st)
	}
	if opts.ProxyErrorLimit != proxyErrorLimit {
		t.Fatalf("ProxyErrorLimit = %d, want %d: a dead proxy must not cost the whole connect timeout", opts.ProxyErrorLimit, proxyErrorLimit)
	}
}

func TestActiveLocationRoundTripAndDisconnect(t *testing.T) {
	withCity(t, nil)
	owned := exec.Command("sleep", "30")
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := ovpn.NewForTest(owned)
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: &fastvpnServer{Country: "Ecuador", City: "Quito"}, location: "Ecuador"}
	activeMu.Unlock()
	if got := (FastVPN{}).ActiveLocation(context.Background()); got != "Ecuador" {
		t.Fatalf("ActiveLocation = %q, want Ecuador", got)
	}
	if got := activeRegion(); got != "Ecuador - Quito" {
		t.Fatalf("activeRegion = %q", got)
	}
	if err := (FastVPN{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (FastVPN{}).ActiveLocation(context.Background()) != "" || activeRegion() != "" {
		t.Fatal("Disconnect must clear the active connection")
	}
	select {
	case <-tunnel.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect left the owned process running")
	}
}
