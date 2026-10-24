package hidemyass

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This performs real TLS server verification and device authentication, using
// OpenVPN's null device to leave the host's interfaces and routes untouched.
// It is separate from TestLiveTunnel: it cannot prove traffic forwarding.
func TestLiveOpenVPNControl(t *testing.T) {
	if os.Getenv("HIDEMYASS_LIVE_CONTROL_TEST") != "1" {
		t.Skip("explicit HMA live control test is disabled")
	}
	if os.Getenv("HIDEMYASS_DEVICE_ID") == "" {
		t.Fatal("set an explicit development device identity")
	}
	if os.Getenv("HIDEMYASS_STATE_DIR") == "" {
		t.Setenv("HIDEMYASS_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	}
	resetHMA(t)
	t.Cleanup(func() { resetHMA(t) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := (HideMyAss{}).Login(ctx); err != nil {
		t.Fatal(err)
	}
	hmaState.mu.RLock()
	saved, backend := hmaState.device, hmaState.backend
	keys := locationKeys(hmaState.countries, "GB")
	hmaState.mu.RUnlock()
	if len(keys) == 0 {
		t.Fatal("no active UK location")
	}
	servers, err := backend.servers(ctx, saved.Session, keys[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "hma-control-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "m.sock")
	raw, err := openVPNConfig(servers[0], saved.Credentials, socket)
	if err != nil {
		t.Fatal(err)
	}
	config := strings.ReplaceAll(string(raw), "dev "+tunnelInterface+"\ndev-type tun", "dev null")
	config = strings.ReplaceAll(config, "redirect-gateway def1", "ifconfig-noexec\nroute-noexec")
	path := filepath.Join(dir, "control.ovpn")
	if err := writePrivate(path, []byte(config)); err != nil {
		t.Fatal(err)
	}
	tunnel, err := launchOpenVPN(ctx, path, socket, saved.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.stop(context.Background())
	if tunnel.address() == "" {
		t.Fatal("native authentication did not negotiate a virtual IP")
	}
	if err := tunnel.stop(ctx); err != nil {
		t.Fatal(err)
	}
	if tunnel.address() != "" {
		t.Fatal("stopped transport retained a virtual IP")
	}
	t.Log("Native account, device credentials, OpenVPN server verification, management authentication, and owned-process cleanup passed")
}

// Run only inside an isolated Linux network namespace/container with TUN
// and NET_ADMIN available. The test creates/reuses the explicitly configured development device.
func TestLiveTunnel(t *testing.T) {
	if os.Getenv("HIDEMYASS_LIVE_TUNNEL_TEST") != "1" {
		t.Skip("explicit HMA live tunnel test is disabled")
	}
	if os.Getenv("HIDEMYASS_DEVICE_ID") == "" {
		t.Fatal("set an explicit development device identity")
	}
	if os.Getenv("HIDEMYASS_STATE_DIR") == "" {
		t.Setenv("HIDEMYASS_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	}
	resetHMA(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	h := HideMyAss{}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = h.Disconnect(cleanup)
		resetHMA(t)
	})
	baseline := probePublicIP(ctx, nil)
	if baseline == "" {
		t.Fatal("baseline public-IP probe failed")
	}
	if err := h.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.Locations(ctx)) == 0 {
		t.Fatal("no countries returned")
	}
	hmaState.mu.RLock()
	udid := hmaState.device.Session.UDID
	hmaState.mu.RUnlock()
	if err := h.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if hmaState.device.Session.UDID != udid {
		t.Fatal("device identity changed when reusing cached credentials")
	}
	status := h.Connect(ctx, "GB")
	if !status.Connected {
		t.Fatal("HMA OpenVPN tunnel did not establish")
	}
	if status.Location != "GB" || h.ActiveLocation(ctx) != "GB" {
		t.Fatal("active location did not round-trip")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return dialTunnel(ctx, addr) }}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	response, err := client.Get("https://icanhazip.com")
	if err != nil {
		t.Fatal("proxy tunnel public-IP probe failed")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 128))
	_ = response.Body.Close()
	if err != nil {
		t.Fatal("read proxy exit IP")
	}
	exit := net.ParseIP(strings.TrimSpace(string(raw)))
	if exit == nil || exit.String() == baseline {
		t.Fatal("proxy traffic did not change exit IP")
	}
	t.Log("Native OpenVPN and proxy exit-IP checks passed")
	if err := h.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Connected(ctx) || h.ActiveLocation(ctx) != "" {
		t.Fatal("disconnect left an active tunnel")
	}
	if _, err := dialTunnel(ctx, "example.invalid:443"); err == nil {
		t.Fatal("proxy did not fail closed after disconnect")
	}
}
