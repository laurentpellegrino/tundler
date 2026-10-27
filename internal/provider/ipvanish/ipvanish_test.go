package ipvanish

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseFilename(t *testing.T) {
	tests := []struct {
		filename string
		want     ipvanishServer
		ok       bool
	}{
		{
			filename: "ipvanish-US-New-York-nyc-c28.ovpn",
			want: ipvanishServer{
				Country: "United States", CC: "US", City: "New York",
				Hostname: "nyc-c28.ipvanish.com",
				Filename: "ipvanish-US-New-York-nyc-c28.ovpn",
			},
			ok: true,
		},
		{
			filename: "ipvanish-UK-London-lon-b23.ovpn",
			want: ipvanishServer{
				Country: "United Kingdom", CC: "UK", City: "London",
				Hostname: "lon-b23.ipvanish.com",
				Filename: "ipvanish-UK-London-lon-b23.ovpn",
			},
			ok: true,
		},
		{
			filename: "ipvanish-AD-Andorra-la-Vella---Virtual-adv-c01.ovpn",
			want: ipvanishServer{
				Country: "Andorra", CC: "AD", City: "Andorra la Vella",
				Hostname: "adv-c01.ipvanish.com", Virtual: true,
				Filename: "ipvanish-AD-Andorra-la-Vella---Virtual-adv-c01.ovpn",
			},
			ok: true,
		},
		{
			// Server number with three digits.
			filename: "ipvanish-DE-Frankfurt-fra-a123.ovpn",
			want: ipvanishServer{
				Country: "Germany", CC: "DE", City: "Frankfurt",
				Hostname: "fra-a123.ipvanish.com",
				Filename: "ipvanish-DE-Frankfurt-fra-a123.ovpn",
			},
			ok: true,
		},
		{
			// Unknown CC falls back to the raw code.
			filename: "ipvanish-XX-Mystery-mys-a01.ovpn",
			want: ipvanishServer{
				Country: "XX", CC: "XX", City: "Mystery",
				Hostname: "mys-a01.ipvanish.com",
				Filename: "ipvanish-XX-Mystery-mys-a01.ovpn",
			},
			ok: true,
		},
		{filename: "not-an-ipvanish-config.ovpn", ok: false},
		{filename: "ipvanish-US-New-York.ovpn", ok: false},
	}

	for _, tc := range tests {
		got, ok := parseFilename(tc.filename)
		if ok != tc.ok {
			t.Errorf("parseFilename(%q) ok = %v, want %v", tc.filename, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if got != tc.want {
			t.Errorf("parseFilename(%q)\n got: %+v\nwant: %+v", tc.filename, got, tc.want)
		}
	}
}

// vendorConfig is the shape of a real IPVanish .ovpn, including the
// directives OpenVPN 2.6 rejects or that we take over.
const vendorConfig = `client
dev tun
proto udp
remote nyc-c28.ipvanish.com 443
resolv-retry infinite
nobind
persist-key
persist-tun
persist-remote-ip
ca ca.ipvanish.com.crt
verify-x509-name nyc-c28.ipvanish.com name
auth-user-pass
comp-lzo
verb 3
auth SHA256
cipher AES-256-CBC
keysize 256
tls-cipher TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-DSS-WITH-AES-256-CBC-SHA:TLS-RSA-WITH-AES-256-CBC-SHA
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
auth-user-pass looks like a directive but is key material
cipher AES-256-CBC
-----END OpenVPN Static key V1-----
</tls-auth>
`

func TestOpenVPNConfigKeepsTransportAndOwnsLifecycle(t *testing.T) {
	raw, err := openVPNConfig([]byte(vendorConfig), "/run/ipvanish/openvpn-1/management.sock")
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{
		"remote nyc-c28.ipvanish.com 443", "proto udp", "ca ca.ipvanish.com.crt",
		"verify-x509-name nyc-c28.ipvanish.com name", "auth SHA256", "<tls-auth>",
		"dev " + tunnelInterface, "management \"/run/ipvanish/openvpn-1/management.sock\" unix",
		"management-query-passwords", "management-hold", "auth-nocache", "redirect-gateway def1",
		"connect-retry-max 1", "tun-mtu 1320", "mssfix 1280", "verb 0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("config missing %q", want)
		}
	}
	// Dropped vendor directives: at most once each, and only ours.
	for _, dropped := range []string{"dev tun\n", "verb 3", "comp-lzo", "keysize", "tls-cipher", "cipher AES-256-CBC\nkeysize"} {
		if strings.Contains(got, dropped) {
			t.Errorf("config kept %q", dropped)
		}
	}
	// Exactly one bare auth-user-pass line outside the inline block
	// (the vendor's own was dropped), never one with a file argument.
	outside := inlineBlockRe.ReplaceAllString(got, "")
	if strings.Count(outside, "\nauth-user-pass\n") != 1 || strings.Contains(outside, "auth-user-pass ") {
		t.Fatalf("auth-user-pass must appear once, bare, so the password comes over the management socket:\n%s", outside)
	}
	// The inline block is verbatim, directive look-alikes included.
	if !strings.Contains(got, "auth-user-pass looks like a directive but is key material\ncipher AES-256-CBC\n-----END") {
		t.Fatal("inline block was altered")
	}
	if _, err := openVPNConfig([]byte("client\nproto udp\n"), "/m.sock"); err == nil {
		t.Fatal("a config without remote must be rejected")
	}
	if _, err := openVPNConfig([]byte(vendorConfig), "/bad\"quote.sock"); err == nil {
		t.Fatal("a socket path that breaks quoting must be rejected")
	}
}

// managementFixture runs a real owned child (a sleep standing in for
// openvpn) plus a Unix management peer, so lifecycle and credential
// handling are exercised without routes or a TUN interface.
func managementFixture(t *testing.T, user, pass string, authenticate bool) (string, <-chan net.Conn) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ipv-mgmt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "m.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "openvpn"), []byte("#!/bin/sh\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	connected := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		scanner := bufio.NewScanner(conn)
		for range 2 { // "state on", "hold release"
			if !scanner.Scan() {
				return
			}
		}
		if !authenticate {
			connected <- conn
			return
		}
		_, _ = io.WriteString(conn, ">PASSWORD:Need 'Auth' username/password\n")
		for _, want := range []string{"username \"Auth\" " + strconv.Quote(user), "password \"Auth\" " + strconv.Quote(pass)} {
			if !scanner.Scan() || scanner.Text() != want {
				t.Error("management credential exchange mismatch")
				_ = conn.Close()
				return
			}
		}
		_, _ = io.WriteString(conn, ">STATE:1,CONNECTED,SUCCESS,10.20.30.40,192.0.2.10,1194\n")
		connected <- conn
	}()
	return path, connected
}

func TestManagedOpenVPNExchangesCredentialsAndOwnsItsChild(t *testing.T) {
	const user, pass = "synthetic-user", "synthetic \"quoted\\password"
	socket, peer := managementFixture(t, user, pass, true)
	t.Setenv("TUNDLER_ACCOUNT_PASSWORD", "synthetic-account-secret")
	ctx, cancel := context.WithCancel(context.Background())
	tunnel, err := launchOpenVPN(ctx, t.TempDir(), "client.ovpn", socket, user, pass)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.stop(context.Background()) })
	cancel() // the connect deadline must not become the tunnel lifetime
	if tunnel.address() != "10.20.30.40" {
		t.Fatal("connected virtual IP not published")
	}
	for _, entry := range tunnel.cmd.Env {
		if strings.Contains(entry, "synthetic-account-secret") {
			t.Fatal("transport inherited the account secret")
		}
	}
	conn := <-peer
	_, _ = io.WriteString(conn, ">STATE:2,RECONNECTING,ping-restart,,,,\n")
	deadline := time.Now().Add(time.Second)
	for tunnel.address() != "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if tunnel.address() != "" {
		t.Fatal("reconnecting transport retained a usable virtual IP")
	}
	_ = conn.Close()
	select {
	case <-tunnel.done:
	case <-time.After(2 * time.Second):
		t.Fatal("management loss left the owned process running")
	}
}

func TestManagedOpenVPNClassifiesAuthFailedWithoutLeakingThePassword(t *testing.T) {
	const user, pass = "synthetic-user", "synthetic-password"
	socket, peer := managementFixture(t, user, pass, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		conn := <-peer
		_, _ = io.WriteString(conn, ">PASSWORD:Verification Failed: 'Auth' ['"+pass+"']\n")
	}()
	tunnel, err := launchOpenVPN(ctx, t.TempDir(), "client.ovpn", socket, user, pass)
	if tunnel != nil || !errors.Is(err, errAuthFailed) {
		t.Fatalf("AUTH_FAILED was not classified: tunnel=%v err=%v", tunnel, err)
	}
	if strings.Contains(err.Error(), pass) {
		t.Fatal("authentication error exposed the password")
	}
}

func TestManagedOpenVPNCancellationStopsPendingConnection(t *testing.T) {
	socket, peer := managementFixture(t, "u", "p", false)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-peer; cancel() }()
	if tunnel, err := launchOpenVPN(ctx, t.TempDir(), "client.ovpn", socket, "u", "p"); err == nil || tunnel != nil {
		t.Fatal("cancelled connection succeeded")
	}
}

func TestStopTerminatesOnlyTheOwnedChild(t *testing.T) {
	unrelated := exec.Command("sleep", "30")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unrelated.Process.Kill(); _ = unrelated.Wait() })
	owned := exec.Command("sleep", "30")
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := &openVPNTunnel{cmd: owned, done: make(chan struct{}), events: make(chan struct{}, 1)}
	go func() { _ = owned.Wait(); close(tunnel.done) }()
	if err := tunnel.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := unrelated.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("stop reached an unrelated process")
	}
}

func resetActive(t *testing.T) {
	t.Helper()
	activeMu.Lock()
	current = nil
	activeMu.Unlock()
}

func TestActiveLocationRoundTripAndDisconnect(t *testing.T) {
	resetActive(t)
	t.Cleanup(func() { resetActive(t) })
	if got := (IPVanish{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
	owned := exec.Command("sleep", "30")
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := &openVPNTunnel{cmd: owned, done: make(chan struct{}), events: make(chan struct{}, 1)}
	go func() { _ = owned.Wait(); close(tunnel.done) }()
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: &ipvanishServer{Country: "United States", City: "New York"}, location: "United States"}
	activeMu.Unlock()
	if got := (IPVanish{}).ActiveLocation(context.Background()); got != "United States" {
		t.Fatalf("ActiveLocation = %q, want the verbatim Connect argument", got)
	}
	if got := activeRegion(); got != "United States - New York" {
		t.Fatalf("activeRegion = %q", got)
	}
	if err := (IPVanish{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if (IPVanish{}).ActiveLocation(context.Background()) != "" || activeRegion() != "" {
		t.Fatal("Disconnect must clear the active connection")
	}
	select {
	case <-tunnel.done:
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect left the owned process running")
	}
}

func TestFindServersMatchesCountryCodeAndCity(t *testing.T) {
	servers := []ipvanishServer{
		{Country: "United States", CC: "US", City: "New York"},
		{Country: "United States", CC: "US", City: "Chicago"},
		{Country: "Germany", CC: "DE", City: "Frankfurt"},
	}
	if n := len(findServers(servers, "united states")); n != 2 {
		t.Fatalf("country match = %d, want 2", n)
	}
	if n := len(findServers(servers, "de")); n != 1 {
		t.Fatalf("code match = %d, want 1", n)
	}
	if n := len(findServers(servers, "chicago")); n != 1 {
		t.Fatalf("city match = %d, want 1", n)
	}
	if n := len(findServers(servers, "")); n != 3 {
		t.Fatalf("empty location = %d, want all", n)
	}
}
