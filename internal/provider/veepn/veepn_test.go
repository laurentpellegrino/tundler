package veepn

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

const sampleOVPN = `client
pull
dev tun
proto udp
auth-user-pass
sndbuf 0
rcvbuf 0
remote 146.70.19.146 23499
resolv-retry infinite
remote-random
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
setenv opt block-outside-dns
key-direction 1
verb 3
reneg-sec 0
fast-io
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
<ca>
-----BEGIN CERTIFICATE-----
xxx
-----END CERTIFICATE-----
</ca>
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
auth-user-pass is key material here, not a directive
-----END OpenVPN Static key V1-----
</tls-auth>
`

func resetState(t *testing.T) {
	t.Helper()
	serverCacheMu.Lock()
	serverCache = nil
	serverCacheMu.Unlock()
	activeMu.Lock()
	current = nil
	loggedIn = false
	activeMu.Unlock()
}

func fixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, fn := range []string{
		"ae.udp.veepn.com.ovpn", "ae.tcp.veepn.com.ovpn",
		"au-nsw.udp.veepn.com.ovpn", "au-nsw.tcp.veepn.com.ovpn",
		"notes.txt",
	} {
		if err := os.WriteFile(filepath.Join(dir, fn), []byte(sampleOVPN), 0644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VEEPN_CONFIG_DIR", dir)
	return dir
}

func TestLocationsLoginAndCandidates(t *testing.T) {
	resetState(t)
	fixtureDir(t)
	t.Setenv("POD_NAME", "tundler-tunnel-veepn-0")
	t.Setenv("POD_0_VEEPN_USERNAME", "user0")
	t.Setenv("POD_0_VEEPN_PASSWORD", "pass0")
	v := VeePN{}
	// Locations() collapses udp+tcp into distinct location codes.
	if got := strings.Join(v.Locations(context.Background()), ","); got != "ae,au-nsw" {
		t.Fatalf("Locations() = %q, want \"ae,au-nsw\"", got)
	}
	// Login validates per-pod creds + presence of configs.
	if err := v.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !v.LoggedIn(context.Background()) {
		t.Fatal("LoggedIn must be true after Login")
	}
	servers, _ := loadServers()
	tries := candidates(servers, "AU-NSW")
	if len(tries) != 2 || tries[0].Proto != "udp" || tries[1].Proto != "tcp" || tries[0].Filename != "au-nsw.udp.veepn.com.ovpn" {
		t.Fatalf("candidates(au-nsw) = %+v, want udp then tcp", tries)
	}
	if len(candidates(servers, "zz")) != 0 {
		t.Fatal("unknown location must have no candidates")
	}
}

func TestLoginRequiresThisPodsCredential(t *testing.T) {
	resetState(t)
	fixtureDir(t)
	t.Setenv("POD_NAME", "tundler-tunnel-veepn-3")
	t.Setenv("POD_3_VEEPN_USERNAME", "")
	t.Setenv("POD_3_VEEPN_PASSWORD", "")
	err := (VeePN{}).Login(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no accounts configured for provider veepn") {
		t.Fatalf("Login without pod-3 creds = %v, want the accounts hint", err)
	}
	// Another pod's credential does not count as this pod's.
	t.Setenv("POD_0_VEEPN_USERNAME", "user0")
	t.Setenv("POD_0_VEEPN_PASSWORD", "pass0")
	if err := (VeePN{}).Login(context.Background()); err == nil {
		t.Fatal("pod 3 must not log in with pod 0's credential")
	}
}

func TestOpenVPNConfigKeepsVendorTransportAndKeys(t *testing.T) {
	raw, err := openVPNConfig([]byte(sampleOVPN), "/run/veepn/openvpn-1/management.sock")
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{
		"remote 146.70.19.146 23499\n", "proto udp\n", "cipher AES-256-CBC\n", "key-direction 1\n", "auth SHA512\n",
		"tun-mtu 1500\n", "mssfix 1450\n", "-----BEGIN CERTIFICATE-----", "-----BEGIN OpenVPN Static key V1-----",
		"dev " + tunnelInterface + "\n", "management \"/run/veepn/openvpn-1/management.sock\" unix\n",
		"management-query-passwords\n", "management-hold\n", "auth-nocache\n", "connect-retry-max 1\n", "connect-timeout 15\n", "verb 0\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("config missing %q", want)
		}
	}
	for _, dropped := range []string{"dev tun\n", "verb 3", "auth-user-pass /"} {
		if strings.Contains(got, dropped) {
			t.Errorf("config kept %q", dropped)
		}
	}
	// Exactly one bare auth-user-pass outside the inline blocks, the
	// tls-auth block verbatim (its look-alike line included).
	outside := inlineBlockRe.ReplaceAllString(got, "")
	if strings.Count(outside, "\nauth-user-pass\n") != 1 {
		t.Fatalf("auth-user-pass must appear exactly once, bare:\n%s", outside)
	}
	if !strings.Contains(got, "auth-user-pass is key material here, not a directive\n-----END") {
		t.Fatal("tls-auth block was altered")
	}
	if _, err := openVPNConfig([]byte("client\nproto udp\n"), "/m.sock"); err == nil {
		t.Fatal("a config without remote must be rejected")
	}
	if _, err := openVPNConfig([]byte(sampleOVPN), "/bad\"quote.sock"); err == nil {
		t.Fatal("a socket path that breaks quoting must be rejected")
	}
}

func TestActiveLocationRoundTripAndDisconnect(t *testing.T) {
	resetState(t)
	if got := (VeePN{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
	owned := exec.Command("sleep", "30")
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := ovpn.NewForTest(owned)
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: &veepnServer{Location: "au-nsw", Proto: "udp"}, location: "au-nsw"}
	activeMu.Unlock()
	if got := (VeePN{}).ActiveLocation(context.Background()); got != "au-nsw" {
		t.Fatalf("ActiveLocation = %q, want the verbatim Connect argument", got)
	}
	if err := (VeePN{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (VeePN{}).ActiveLocation(context.Background()) != "" {
		t.Fatal("Disconnect must clear the active connection")
	}
	select {
	case <-tunnel.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect left the owned process running")
	}
}
