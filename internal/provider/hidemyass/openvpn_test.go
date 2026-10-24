package hidemyass

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
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

func testVPNCredentials(t *testing.T) vpnCredentials {
	return vpnCredentials{DeviceUDID: "synthetic-device", DevicePassword: "synthetic-transport-password", OpenVPNCA: testCA(t, time.Now().Add(time.Hour))}
}

func testCA(t *testing.T, expires time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic HMA CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: expires}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestOpenVPNTrustRotationIgnoresRetiredRoots(t *testing.T) {
	creds := testVPNCredentials(t)
	current := creds.OpenVPNCA
	expired := testCA(t, time.Now().Add(-time.Hour))
	creds.OpenVPNCA = expired + "\n" + current + "\n\n"
	server := vpnServer{IP: "192.0.2.10", Protocol: "openvpn", UDPPorts: []int{1194}}
	raw, err := openVPNConfig(server, creds, "/private/m.sock")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), expired) || !strings.Contains(string(raw), current) {
		t.Fatal("retired CA was trusted or current CA omitted")
	}
	creds.OpenVPNCA = expired
	if _, err := openVPNConfig(server, creds, "/private/m.sock"); err == nil {
		t.Fatal("accepted a bundle with no valid CA")
	}
}

func TestOpenVPNConfigAuthenticatesServerWithoutPersistingPassword(t *testing.T) {
	creds := testVPNCredentials(t)
	server := vpnServer{IP: "192.0.2.10", Protocol: "openvpn", UDPPorts: []int{1194}}
	for _, ca := range []string{creds.OpenVPNCA, base64.StdEncoding.EncodeToString([]byte(creds.OpenVPNCA))} {
		creds.OpenVPNCA = ca
		raw, err := openVPNConfig(server, creds, "/private/management.sock")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"remote-cert-tls server", "verify-x509-name openvpn.gen-vpn.com name", "tls-version-min 1.2", "management-query-passwords", "management-hold", "auth-nocache", "redirect-gateway def1", "dev " + tunnelInterface} {
			if !strings.Contains(string(raw), want) {
				t.Errorf("configuration missing %q", want)
			}
		}
		if strings.Contains(string(raw), creds.DeviceUDID) || strings.Contains(string(raw), creds.DevicePassword) {
			t.Fatal("configuration persisted device credentials")
		}
	}
	for _, broken := range []vpnServer{{IP: "192.0.2.1\nremote evil", Protocol: "openvpn", UDPPorts: []int{1194}}, {IP: "192.0.2.1", Protocol: "ipsec", UDPPorts: []int{500}}, {IP: "192.0.2.1", Protocol: "openvpn", UDPPorts: []int{-1, 70000}}} {
		if _, err := openVPNConfig(broken, creds, "/private/m.sock"); err == nil {
			t.Error("accepted an invalid endpoint")
		}
	}
	creds.OpenVPNCA = "</ca>\nremote untrusted.invalid"
	if _, err := openVPNConfig(server, creds, "/private/m.sock"); err == nil {
		t.Fatal("accepted invalid vendor CA data")
	}
}

// A real owned child plus a Unix management peer exercises lifecycle behavior
// without changing routes or requiring a TUN interface in ordinary unit tests.
func managementFixture(t *testing.T, creds vpnCredentials, authenticate bool) (string, string, <-chan net.Conn) {
	t.Helper()
	dir, err := os.MkdirTemp("", "hma-mgmt-")
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
		for range 2 {
			if !scanner.Scan() {
				return
			}
		}
		if !authenticate {
			connected <- conn
			return
		}
		_, _ = io.WriteString(conn, ">PASSWORD:Need 'Auth' username/password\n")
		for _, want := range []string{"username \"Auth\" " + strconv.Quote(creds.DeviceUDID), "password \"Auth\" " + strconv.Quote(creds.DevicePassword)} {
			if !scanner.Scan() || scanner.Text() != want {
				t.Error("management credential exchange mismatch")
				_ = conn.Close()
				return
			}
		}
		_, _ = io.WriteString(conn, ">STATE:1,CONNECTED,SUCCESS,10.20.30.40,192.0.2.10,1194\n")
		connected <- conn
	}()
	return filepath.Join(dir, "config"), path, connected
}

func TestManagedOpenVPNOwnsOnlyItsChildAndFailsClosedOnRestart(t *testing.T) {
	creds := vpnCredentials{DeviceUDID: "synthetic-user", DevicePassword: "synthetic \"quoted\\password"}
	config, socket, peer := managementFixture(t, creds, true)
	t.Setenv("TUNDLER_ACCOUNT_PASSWORD", "synthetic-account-secret")
	unrelated := exec.Command("sleep", "30")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unrelated.Process.Kill(); _ = unrelated.Wait() })
	ctx, cancel := context.WithCancel(context.Background())
	tunnel, err := launchOpenVPN(ctx, config, socket, creds)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.stop(context.Background()) })
	cancel() // The connection request lifetime must not become the tunnel lifetime.
	if tunnel.address() != "10.20.30.40" {
		t.Fatal("connected virtual IP not published")
	}
	for _, entry := range tunnel.cmd.Env {
		if strings.Contains(entry, "synthetic-account-secret") {
			t.Fatal("transport inherited account secret")
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
	if err := unrelated.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("transport cleanup stopped an unrelated process")
	}
}

func TestManagedOpenVPNCancellationStopsPendingConnection(t *testing.T) {
	creds := vpnCredentials{DeviceUDID: "synthetic-user", DevicePassword: "synthetic-password"}
	config, socket, peer := managementFixture(t, creds, false)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-peer; cancel() }()
	if tunnel, err := launchOpenVPN(ctx, config, socket, creds); err == nil || tunnel != nil {
		t.Fatal("canceled connection succeeded")
	}
}

func TestManagedOpenVPNAuthenticationRejectionIsRedacted(t *testing.T) {
	creds := vpnCredentials{DeviceUDID: "synthetic-user", DevicePassword: "synthetic-password"}
	config, socket, peer := managementFixture(t, creds, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		conn := <-peer
		_, _ = io.WriteString(conn, ">PASSWORD:Verification Failed: 'Auth' ['synthetic-password']\n")
	}()
	tunnel, err := launchOpenVPN(ctx, config, socket, creds)
	if tunnel != nil || !errors.Is(err, errTransportAuthentication) {
		t.Fatal("explicit authentication rejection was not classified")
	}
	if strings.Contains(err.Error(), creds.DevicePassword) {
		t.Fatal("authentication error exposed a device password")
	}
}
