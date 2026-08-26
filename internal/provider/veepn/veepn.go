// Package veepn drives VeePN over OpenVPN directly (no provider daemon),
// the same OpenVPN-direct shape as fastvpn / ovpn / purevpn — but with
// per-pod credentials (each pod owns one VeePN manual-config
// username/password, like cyberghost/mullvad) rather than a single
// shared credential.
//
// VeePN's per-location OpenVPN configs are NOT templatable: every one of
// the ~135 locations is fully self-contained, carrying its OWN embedded
// CA + tls-auth key + server IP (verified: 135 distinct CAs). So instead
// of generating a .ovpn from a template + shared CA (cyberghost), we BAKE
// the actual upstream .ovpn files into the image (a zip from the
// `veepn-configs` GitHub release — see docker/providers/veepn/install.sh)
// and at Connect() pick the chosen location's file, rewriting only its
// bare `auth-user-pass` directive to point at this pod's credentials.
//
// The config archive lives behind VeePN's Cloudflare-gated account
// dashboard, so it's refreshed by a headless-browser workflow
// (.github/workflows/update-veepn-configs.yml) that logs in, downloads
// "all configs", and republishes the release. The tunnels themselves
// connect straight to the server IPs (no Cloudflare), so a stale list
// only costs the few locations whose IPs have since rotated.
//
// Per-pod credentials: each VeePN device-credential consumes one of the
// account's connection slots (Pro = 10), so each pod owns exactly one —
// a Slots=1 account in the accounts model. Account mode reads
// /etc/tundler/accounts/<id>/{username,password}; the legacy shim keeps
// POD_<N>_VEEPN_USERNAME / POD_<N>_VEEPN_PASSWORD env pairs working
// (one pair per pod from OpenBao vpn/veepn/pod-<n>).
package veepn

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	name             = "veepn"
	defaultConfigDir = "/etc/veepn/configs"
	activeConfigName = "active.ovpn"
	credentialsName  = "auth.txt"
)

var (
	// Upstream filename format: <location>.<proto>.veepn.com.ovpn
	// e.g. ae.udp.veepn.com.ovpn, au-nsw.tcp.veepn.com.ovpn.
	filenameRe = regexp.MustCompile(`^(.+)\.(udp|tcp)\.veepn\.com\.ovpn$`)
	// Bare `auth-user-pass` directive (no file argument) — present in
	// every upstream .ovpn. We rewrite it so openvpn reads our per-pod
	// credentials file instead of prompting on the (absent) console.
	authUserPassRe = regexp.MustCompile(`(?m)^auth-user-pass\s*$`)

	serverCache   []veepnServer
	serverCacheMu sync.RWMutex

	activeServer   *veepnServer
	activeLocation string
	activeMu       sync.RWMutex
	loggedIn       bool
)

// veepnServer is one baked .ovpn (one location, one protocol). udp is
// preferred at connect time; tcp is the fallback.
type veepnServer struct {
	Location string // e.g. "ae", "au-nsw", "albania"
	Proto    string // "udp" | "tcp"
	Filename string
}

type VeePN struct{}

func init() {
	provider.Registry[name] = VeePN{}
	accounts.RegisterLegacyShim(name, accounts.LegacyPerPodEnv("POD_%d_VEEPN_", map[string]string{
		accounts.FieldUsername: "USERNAME",
		accounts.FieldPassword: "PASSWORD",
	}))
}

func configDir() string {
	if d := os.Getenv("VEEPN_CONFIG_DIR"); d != "" {
		return d
	}
	return defaultConfigDir
}

// getCredentials returns this pod's VeePN manual-config username/password
// (its Slots=1 account; POD_<n>_VEEPN_* via the legacy shim).
func getCredentials() (user, pass string, err error) {
	acct, err := accounts.Current(name)
	if err != nil {
		return "", "", err
	}
	user, err = acct.Require(accounts.FieldUsername)
	if err != nil {
		return "", "", err
	}
	pass, err = acct.Require(accounts.FieldPassword)
	if err != nil {
		return "", "", err
	}
	return user, pass, nil
}

// loadServers indexes the baked .ovpn files, cached for the process
// lifetime (the directory is static — refreshed only by an image rebuild).
func loadServers() ([]veepnServer, error) {
	serverCacheMu.RLock()
	if len(serverCache) > 0 {
		cached := append([]veepnServer(nil), serverCache...)
		serverCacheMu.RUnlock()
		return cached, nil
	}
	serverCacheMu.RUnlock()

	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()
	if len(serverCache) > 0 {
		return append([]veepnServer(nil), serverCache...), nil
	}

	dir := configDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", dir, err)
	}
	var servers []veepnServer
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := filenameRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		servers = append(servers, veepnServer{Location: m[1], Proto: m[2], Filename: e.Name()})
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no VeePN OpenVPN configs found in %s", dir)
	}
	serverCache = servers
	shared.Debugf("VeePN: loaded %d OpenVPN configs", len(servers))
	return append([]veepnServer(nil), servers...), nil
}

// pickServer returns the udp config for the location (tcp fallback).
func pickServer(servers []veepnServer, location string) *veepnServer {
	want := strings.ToLower(strings.TrimSpace(location))
	var udp, tcp *veepnServer
	for i := range servers {
		if strings.ToLower(servers[i].Location) != want {
			continue
		}
		s := servers[i]
		if s.Proto == "udp" {
			udp = &s
		} else {
			tcp = &s
		}
	}
	if udp != nil {
		return udp
	}
	return tcp
}

func writeCredentials(user, pass string) (string, error) {
	return shared.WriteUserPassFile(configDir(), credentialsName, user, pass)
}

func writeActiveConfig(server *veepnServer, credentialsFile string) (string, error) {
	src := filepath.Join(configDir(), server.Filename)
	raw, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", src, err)
	}
	rewritten := authUserPassRe.ReplaceAllString(string(raw), "auth-user-pass "+credentialsFile)
	dst := filepath.Join(configDir(), activeConfigName)
	if err := os.WriteFile(dst, []byte(rewritten), 0600); err != nil {
		return "", fmt.Errorf("write active config: %w", err)
	}
	return dst, nil
}

// isOpenVPNConnected returns true once openvpn's pushed redirect-gateway
// has taken effect — a route lookup for an arbitrary public address
// resolves via tun0. Same default-route gating as the other
// openvpn-direct providers.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev tun0 ")
}

// ---- VPNProvider ------------------------------------------------------

// Login is a no-op auth check for OpenVPN-direct: it just verifies this
// pod's credentials are present and configs are baked.
func (v VeePN) Login(ctx context.Context) error {
	if _, _, err := getCredentials(); err != nil {
		return err
	}
	if _, err := loadServers(); err != nil {
		return err
	}
	activeMu.Lock()
	loggedIn = true
	activeMu.Unlock()
	return nil
}

func (VeePN) Logout(context.Context) error {
	activeMu.Lock()
	loggedIn = false
	activeMu.Unlock()
	return nil
}

func (VeePN) LoggedIn(context.Context) bool {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return loggedIn
}

func (VeePN) Locations(context.Context) []string {
	servers, err := loadServers()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var locations []string
	for _, s := range servers {
		if seen[s.Location] {
			continue
		}
		seen[s.Location] = true
		locations = append(locations, s.Location)
	}
	sort.Strings(locations)
	return locations
}

func (v VeePN) Connect(ctx context.Context, location string) provider.Status {
	user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("VeePN: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	servers, err := loadServers()
	if err != nil {
		shared.Debugf("VeePN: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	server := pickServer(servers, location)
	if server == nil {
		shared.Debugf("VeePN: no config for location %q", location)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	authPath, err := writeCredentials(user, pass)
	if err != nil {
		shared.Debugf("VeePN: write credentials: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	if _, err := writeActiveConfig(server, authPath); err != nil {
		shared.Debugf("VeePN: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	if _, err := shared.RunCmd(ctx, "openvpn",
		"--cd", configDir(),
		"--config", activeConfigName,
		"--daemon"); err != nil {
		shared.Debugf("VeePN: failed to start openvpn: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	for j := 0; j < 60; j++ {
		time.Sleep(500 * time.Millisecond)
		if isOpenVPNConnected() {
			activeMu.Lock()
			activeServer = server
			activeLocation = location
			activeMu.Unlock()
			return v.Status(ctx)
		}
	}
	shared.Debugf("VeePN: connection timeout for %s", server.Filename)
	_, _ = shared.RunCmd(ctx, "pkill", "-SIGTERM", "openvpn")
	return provider.Status{Connected: false, Provider: name, Location: location}
}

func (VeePN) Disconnect(ctx context.Context) error {
	_, _ = shared.RunCmd(ctx, "pkill", "-SIGTERM", "openvpn")
	for j := 0; j < 20; j++ {
		if !isOpenVPNConnected() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	activeMu.Lock()
	activeServer = nil
	activeLocation = ""
	activeMu.Unlock()
	return nil
}

func (VeePN) Connected(context.Context) bool { return isOpenVPNConnected() }

func (v VeePN) Status(context.Context) provider.Status {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if activeServer == nil {
		return provider.Status{Connected: false, Provider: name}
	}
	return provider.Status{
		Connected: true,
		Provider:  name,
		Location:  activeLocation,
		Region:    strings.ToUpper(activeLocation),
	}
}

func (VeePN) ActiveLocation(context.Context) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (VeePN) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, "openvpn", "--version")
	if err != nil && out == "" {
		return "", err
	}
	first := out
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	return strings.TrimSpace(first), nil
}
