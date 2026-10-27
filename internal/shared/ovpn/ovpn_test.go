package ovpn

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

// managementFixture runs a real owned child (a sleep standing in for
// openvpn) plus a Unix management peer, so lifecycle and credential
// handling are exercised without routes or a TUN interface.
func managementFixture(t *testing.T, user, pass string, authenticate bool) (string, <-chan net.Conn) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ovpn-mgmt-")
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

func TestDirectivesQuoteTheSocket(t *testing.T) {
	d := Directives("/run/x/management.sock")
	for _, want := range []string{"auth-user-pass\n", "auth-nocache\n", "management \"/run/x/management.sock\" unix\n", "management-query-passwords\n", "management-hold\n", "management-signal\n"} {
		if !strings.Contains(d, want) {
			t.Errorf("directives missing %q", want)
		}
	}
	if ValidSocket("/bad\"quote.sock") || ValidSocket(strings.Repeat("a", 108)) || !ValidSocket("/run/ok.sock") {
		t.Fatal("socket validation")
	}
}

func TestLaunchExchangesCredentialsAndOwnsItsChild(t *testing.T) {
	const user, pass = "synthetic-user", "synthetic \"quoted\\password"
	socket, peer := managementFixture(t, user, pass, true)
	t.Setenv("TUNDLER_ACCOUNT_PASSWORD", "synthetic-account-secret")
	ctx, cancel := context.WithCancel(context.Background())
	tunnel, err := Launch(ctx, Options{Name: "Test", CD: t.TempDir(), User: user, Pass: pass}, "client.ovpn", socket)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Stop(context.Background()) })
	cancel() // the connect deadline must not become the tunnel lifetime
	if tunnel.Address() != "10.20.30.40" {
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
	for tunnel.Address() != "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if tunnel.Address() != "" {
		t.Fatal("reconnecting transport retained a usable virtual IP")
	}
	_ = conn.Close()
	select {
	case <-tunnel.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("management loss left the owned process running")
	}
}

func TestLaunchClassifiesAuthFailedWithoutLeakingThePassword(t *testing.T) {
	const user, pass = "synthetic-user", "synthetic-password"
	socket, peer := managementFixture(t, user, pass, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		conn := <-peer
		_, _ = io.WriteString(conn, ">PASSWORD:Verification Failed: 'Auth' ['"+pass+"']\n")
	}()
	tunnel, err := Launch(ctx, Options{Name: "Test", User: user, Pass: pass}, "client.ovpn", socket)
	if tunnel != nil || !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("AUTH_FAILED was not classified: tunnel=%v err=%v", tunnel, err)
	}
	if strings.Contains(err.Error(), pass) {
		t.Fatal("authentication error exposed the password")
	}
}

func TestLaunchCancellationStopsPendingConnection(t *testing.T) {
	socket, peer := managementFixture(t, "u", "p", false)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-peer; cancel() }()
	if tunnel, err := Launch(ctx, Options{Name: "Test", User: "u", Pass: "p"}, "client.ovpn", socket); err == nil || tunnel != nil {
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
	tunnel := NewForTest(owned)
	if err := tunnel.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := unrelated.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("stop reached an unrelated process")
	}
	var nilTunnel *Tunnel
	if nilTunnel.Address() != "" || nilTunnel.Stop(context.Background()) != nil {
		t.Fatal("nil tunnel must be inert")
	}
}

func TestStartWritesAPrivateConfigAndCleansUp(t *testing.T) {
	run := t.TempDir()
	bin := t.TempDir()
	// A stand-in that exits immediately: Start must fail cleanly and
	// remove its connection directory.
	if err := os.WriteFile(filepath.Join(bin, "openvpn"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var seen string
	_, err := Start(context.Background(), Options{Name: "Test", RunDir: run, User: "u", Pass: "p"}, func(socket string) ([]byte, error) {
		seen = socket
		return []byte("client\n" + Directives(socket)), nil
	})
	if err == nil {
		t.Fatal("an openvpn that exits must fail the start")
	}
	if !strings.HasPrefix(seen, run) || !strings.HasSuffix(seen, "management.sock") {
		t.Fatalf("render saw socket %q", seen)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if entries, _ := os.ReadDir(run); len(entries) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("connection directory was not removed after the failed start")
}
