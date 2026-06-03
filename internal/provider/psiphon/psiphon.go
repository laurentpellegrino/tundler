// Package psiphon drives Psiphon as a proxy-chain provider.
//
// Psiphon is a censorship-circumvention system, not a location-selectable
// VPN: there is no account and no real exit-IP control — psiphon-tunnel-core
// auto-selects a server and exposes a LOCAL HTTP CONNECT proxy. We run that
// client (psiphon-client, the upstream ConsoleClient, fetched at image build
// from the psiphon-client GitHub release) as a child process and point the
// in-process CONNECT proxy's dialer at its local proxy — the same dial-func
// seam TunnelBear uses, but the upstream proxy is on 127.0.0.1.
//
// Network params (PropagationChannelId / SponsorId / the remote-server-list
// signing key + bootstrap server entries) are not published in the
// open-source repo; these were extracted from the official Psiphon client
// and embedded here. Exit diversity is whatever Psiphon assigns; a rotation
// (Disconnect+Connect) restarts the client onto a (usually different) server.
package psiphon

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/proxy"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	name = "psiphon"
	// Network identity extracted from the official Psiphon client. Used for
	// stats/sponsor selection, not server auth (servers authenticate via the
	// embedded server entries' SSH keys).
	propagationChannelID = "1BC527D3D09985CF"
	sponsorID            = "92AACC5BABE0944C"

	psiphonBin     = "/usr/local/bin/psiphon-client"
	localProxyPort = 8090
	dataDir        = "/var/lib/psiphon"
)

//go:embed serverlist.dat
var embeddedServerList []byte

//go:embed rsl_pubkey.txt
var rslPublicKey string

var (
	srv *proxy.Server // the in-process CONNECT proxy; set via AttachProxy

	mu             sync.Mutex
	cmd            *exec.Cmd
	connected      bool
	loggedIn       bool
	activeLocation string
)

type Psiphon struct{}

func init() { provider.Registry[name] = Psiphon{} }

// AttachProxy wires the pod's CONNECT proxy and fails closed until Connect.
func (Psiphon) AttachProxy(s *proxy.Server) {
	srv = s
	s.SetDialer(disconnectedDialer)
}

func disconnectedDialer(context.Context, string) (net.Conn, error) {
	return nil, fmt.Errorf("psiphon: tunnel not up")
}

// psiphonConfig is the minimal psiphon-tunnel-core client config.
type psiphonConfig struct {
	ClientVersion                      string `json:"ClientVersion"`
	PropagationChannelId               string `json:"PropagationChannelId"`
	SponsorId                          string `json:"SponsorId"`
	RemoteServerListSignaturePublicKey string `json:"RemoteServerListSignaturePublicKey"`
	LocalHttpProxyPort                 int    `json:"LocalHttpProxyPort"`
	LocalSocksProxyPort                int    `json:"LocalSocksProxyPort"`
	DataRootDirectory                  string `json:"DataRootDirectory"`
	EgressRegion                       string `json:"EgressRegion,omitempty"`
	EmitDiagnosticNotices              bool   `json:"EmitDiagnosticNotices"`
}

func writeRuntimeFiles() (cfgPath, listPath string, err error) {
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		return
	}
	listPath = filepath.Join(dataDir, "serverlist.dat")
	if err = os.WriteFile(listPath, embeddedServerList, 0600); err != nil {
		return
	}
	cfg := psiphonConfig{
		ClientVersion:                      "1",
		PropagationChannelId:               propagationChannelID,
		SponsorId:                          sponsorID,
		RemoteServerListSignaturePublicKey: strings.TrimSpace(rslPublicKey),
		LocalHttpProxyPort:                 localProxyPort,
		LocalSocksProxyPort:                0,
		DataRootDirectory:                  dataDir,
	}
	b, _ := json.Marshal(cfg)
	cfgPath = filepath.Join(dataDir, "config.json")
	err = os.WriteFile(cfgPath, b, 0600)
	return
}

// probeLocalProxy returns true once the local HTTP proxy can CONNECT to an
// upstream — i.e. Psiphon's tunnel is established.
func probeLocalProxy(ctx context.Context) bool {
	c, err := localConnect(ctx, "1.1.1.1:443")
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// localConnect dials the psiphon local HTTP proxy and issues CONNECT target.
func localConnect(ctx context.Context, target string) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var d net.Dialer
	raw, err := d.DialContext(dctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localProxyPort)))
	if err != nil {
		return nil, err
	}
	if dl, ok := dctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		raw.Close()
		return nil, err
	}
	br := bufio.NewReader(raw)
	status, err := br.ReadString('\n')
	if err != nil {
		raw.Close()
		return nil, err
	}
	if !strings.Contains(status, " 200 ") {
		raw.Close()
		return nil, fmt.Errorf("psiphon local proxy CONNECT %s: %s", target, strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			raw.Close()
			return nil, err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	_ = raw.SetDeadline(time.Time{})
	return &bufferedConn{Conn: raw, r: br}, nil
}

func localDialer(ctx context.Context, target string) (net.Conn, error) {
	return localConnect(ctx, target)
}

// ---- VPNProvider ------------------------------------------------------

func (Psiphon) Login(context.Context) error {
	if _, err := os.Stat(psiphonBin); err != nil {
		return fmt.Errorf("psiphon-client binary not found at %s: %w", psiphonBin, err)
	}
	mu.Lock()
	loggedIn = true
	mu.Unlock()
	return nil
}

func (Psiphon) Logout(context.Context) error {
	mu.Lock()
	loggedIn = false
	mu.Unlock()
	return nil
}

func (Psiphon) LoggedIn(context.Context) bool {
	mu.Lock()
	defer mu.Unlock()
	return loggedIn
}

// Locations: Psiphon has no user-selectable exit, so a single placeholder.
func (Psiphon) Locations(context.Context) []string { return []string{"auto"} }

func (p Psiphon) Connect(ctx context.Context, location string) provider.Status {
	if srv == nil {
		return provider.Status{Connected: false, Provider: name}
	}
	p.stopClient() // ensure no stale client

	cfgPath, listPath, err := writeRuntimeFiles()
	if err != nil {
		shared.Debugf("psiphon: write runtime files: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	c := exec.Command(psiphonBin, "-config", cfgPath, "-serverList", listPath)
	c.Stdout, c.Stderr = nil, nil
	if err := c.Start(); err != nil {
		shared.Debugf("psiphon: start client: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	mu.Lock()
	cmd = c
	mu.Unlock()
	// Reap when it exits so a crashed client doesn't become a zombie.
	go func() { _ = c.Wait() }()

	// Wait for the tunnel (psiphon establishes in ~5-40s).
	for i := 0; i < 90; i++ {
		time.Sleep(1 * time.Second)
		if probeLocalProxy(ctx) {
			srv.SetDialer(localDialer)
			mu.Lock()
			connected = true
			activeLocation = "auto"
			mu.Unlock()
			shared.Debugf("psiphon: tunnel up after ~%ds", i+1)
			return provider.Status{Connected: true, Provider: name, Location: "auto"}
		}
	}
	shared.Debugf("psiphon: tunnel did not establish within timeout")
	p.stopClient()
	return provider.Status{Connected: false, Provider: name, Location: location}
}

func (p Psiphon) stopClient() {
	mu.Lock()
	c := cmd
	cmd = nil
	connected = false
	mu.Unlock()
	if c != nil && c.Process != nil {
		_ = c.Process.Kill()
	}
}

func (p Psiphon) Disconnect(context.Context) error {
	p.stopClient()
	mu.Lock()
	activeLocation = ""
	mu.Unlock()
	if srv != nil {
		srv.SetDialer(disconnectedDialer)
	}
	return nil
}

func (Psiphon) Connected(ctx context.Context) bool {
	mu.Lock()
	up := connected && cmd != nil
	mu.Unlock()
	if !up {
		return false
	}
	return probeLocalProxy(ctx)
}

func (Psiphon) Status(context.Context) provider.Status {
	mu.Lock()
	defer mu.Unlock()
	if !connected {
		return provider.Status{Connected: false, Provider: name}
	}
	return provider.Status{Connected: true, Provider: name, Location: activeLocation, Region: "auto"}
}

func (Psiphon) ActiveLocation(context.Context) string {
	mu.Lock()
	defer mu.Unlock()
	return activeLocation
}

func (Psiphon) Version(context.Context) (string, error) { return "psiphon-tunnel-core (console)", nil }

// bufferedConn preserves bytes buffered past the CONNECT response headers.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }
