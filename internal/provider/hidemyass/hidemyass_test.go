package hidemyass

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laurentpellegrino/tundler/internal/proxy"
)

func resetHMA(t *testing.T) {
	t.Helper()
	hmaState.mu.Lock()
	hmaState.active = nil
	hmaState.cleanup = nil
	hmaState.countries = nil
	hmaState.conns = nil
	hmaState.device = savedDevice{}
	hmaState.backend = nil
	hmaState.loggedIn = false
	hmaState.mu.Unlock()
}

func TestLocationsAndSelection(t *testing.T) {
	resetHMA(t)
	t.Cleanup(func() { resetHMA(t) })
	countries := []locationCountry{
		{CC: "US", Country: "USA", Key: "us", State: "active", Cities: []locationCity{{Key: "us-dal", City: "Dallas", State: "active"}, {Key: "us-off", City: "Offline", State: "inactive"}}},
		{CC: "GB", Country: "UK", Key: "gb", State: "active", Cities: []locationCity{{Key: "gb-lon", City: "London", State: "active"}}},
		{CC: "DE", Country: "Germany", Key: "de", State: "inactive"},
	}
	hmaState.countries = countries
	if got := strings.Join((HideMyAss{}).Locations(context.Background()), ","); got != "United Kingdom,United States" {
		t.Fatalf("unexpected country vocabulary %q", got)
	}
	for _, want := range []string{"US", "united states", "USA", "Dallas", "us-dal"} {
		got := locationKeys(countries, want)
		if len(got) != 1 || got[0].Key != "us-dal" {
			t.Errorf("location %q did not select active Dallas server", want)
		}
	}
	if got := locationKeys(countries, "Offline"); len(got) != 0 {
		t.Error("selected inactive city")
	}
	if got := locationKeys(countries, ""); len(got) != 2 {
		t.Error("default selection did not include all active locations")
	}
}

func TestProxyFailsClosedBeforeConnection(t *testing.T) {
	resetHMA(t)
	t.Cleanup(func() { resetHMA(t) })
	server := proxy.New("127.0.0.1:0", "test", "")
	(HideMyAss{}).AttachProxy(server)
	conn, used, err := server.DialUpstream(context.Background(), "example.invalid:443")
	if !used || err == nil || conn != nil {
		t.Fatal("disconnected HMA proxy can fall back to host egress")
	}
}

func TestDisconnectClosesProxySocketsAndClearsLocation(t *testing.T) {
	resetHMA(t)
	t.Cleanup(func() { resetHMA(t) })
	local, remote := net.Pipe()
	defer remote.Close()
	guarded := &tunnelConn{Conn: local}
	hmaState.active = &activeConnection{Location: "United Kingdom"}
	hmaState.conns = map[*tunnelConn]bool{guarded: true}
	if err := (HideMyAss{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hmaState.active != nil || len(hmaState.conns) != 0 {
		t.Fatal("disconnect retained active state")
	}
	var b [1]byte
	if _, err := remote.Read(b[:]); err == nil {
		t.Fatal("old proxy socket remained open")
	}
	if got := (HideMyAss{}).ActiveLocation(context.Background()); got != "" {
		t.Fatal("location survived disconnect")
	}
}

func TestProxyBindsVirtualAddressAndTracksConnections(t *testing.T) {
	resetHMA(t)
	t.Cleanup(func() { resetHMA(t) })
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	tunnel := &openVPNTunnel{done: make(chan struct{}), up: true, vip: "127.0.0.2"}
	hmaState.active = &activeConnection{VIP: tunnel.vip, Tunnel: tunnel}
	conn, err := dialTunnel(context.Background(), listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	remote := <-accepted
	defer remote.Close()
	if !conn.LocalAddr().(*net.TCPAddr).IP.Equal(net.ParseIP("127.0.0.2")) {
		t.Fatal("proxy socket was not bound to the virtual address")
	}
	if len(hmaState.conns) != 1 {
		t.Fatal("proxy socket not tracked for rotation")
	}
	tunnel.mu.Lock()
	tunnel.up = false
	tunnel.mu.Unlock()
	if _, err := dialTunnel(context.Background(), listener.Addr().String()); err == nil {
		t.Fatal("reconnecting proxy fell back to a host dial")
	}
	_ = conn.Close()
	if len(hmaState.conns) != 0 {
		t.Fatal("closed proxy socket retained")
	}
}

func TestDisconnectRetainsFailedFirewallCleanupForRetry(t *testing.T) {
	resetHMA(t)
	t.Cleanup(func() { resetHMA(t) })
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte("#!/bin/sh\nif [ \"$HMA_TEST_FIREWALL_FAILURE\" = 1 ]; then exit 2; fi\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HMA_TEST_FIREWALL_FAILURE", "1")
	candidate := &activeConnection{VIP: "198.18.0.2"}
	hmaState.active = candidate
	if err := (HideMyAss{}).Disconnect(context.Background()); err == nil {
		t.Fatal("firewall query failure was silently ignored")
	}
	if hmaState.active != nil || hmaState.cleanup != candidate {
		t.Fatal("failed cleanup was lost or proxy stayed enabled")
	}
	t.Setenv("HMA_TEST_FIREWALL_FAILURE", "0")
	if err := (HideMyAss{}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hmaState.cleanup != nil {
		t.Fatal("successful retry retained pending cleanup")
	}
}
