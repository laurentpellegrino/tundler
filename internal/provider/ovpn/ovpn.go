// Package ovpn drives OVPN.com over OpenVPN directly (no provider daemon),
// the same OpenVPN-direct shape as cyberghost / fastvpn / ipvanish.
//
// Auth is a single shared username/password (OVPN_USERNAME/OVPN_PASSWORD
// from OpenBao vpn/ovpn) — OVPN allows up to 7 simultaneous connections on
// one credential, so the 7 pods share it (no per-pod keys, unlike the
// WireGuard Mullvad model). The CA cert + tls-auth key are OVPN's static,
// shared, non-secret material (identical in every user's config) and are
// embedded here; the per-server remote is built from the baked datacenter
// list (/etc/ovpn/servers.json, refreshed daily — see install.sh).
package ovpn

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	name             = "ovpn"
	serversFile      = "/etc/ovpn/servers.json"
	configDir        = "/etc/ovpn/openvpn"
	activeConfigName = "active.ovpn"
	credentialsName  = "auth.txt"
)

//go:embed ca.crt
var embeddedCACert string

//go:embed ta.key
var embeddedTLSAuth string

type OVPN struct{}

// Server is one OVPN datacenter from /v1/api/client/datacenters. The
// OpenVPN remote is built as pool-1.prd.<country-lower>.<slug>.ovpn.com
// (e.g. country=DE slug=frankfurt → pool-1.prd.de.frankfurt.ovpn.com),
// matching the hostname pattern in OVPN's downloaded configs.
type Server struct {
	Slug    string `json:"slug"`
	City    string `json:"city"`
	Country string `json:"country"` // ISO code, e.g. "DE"
	IP      string `json:"ip"`
}

func (s Server) hostname() string {
	return fmt.Sprintf("pool-1.prd.%s.%s.ovpn.com", strings.ToLower(s.Country), s.Slug)
}

var (
	serverCache    []Server
	serverCacheMu  sync.RWMutex
	activeServer   *Server
	activeLocation string
	activeMu       sync.RWMutex
	loggedIn       bool
)

func init() { provider.Registry[name] = OVPN{} }

func getCredentials() (string, string, error) {
	user := os.Getenv("OVPN_USERNAME")
	pass := os.Getenv("OVPN_PASSWORD")
	if user == "" || pass == "" {
		return "", "", fmt.Errorf("OVPN_USERNAME and OVPN_PASSWORD environment variables must be set")
	}
	return user, pass, nil
}

// loadServers parses the baked datacenter list (a JSON object keyed by
// index) into the server pool, cached for the process lifetime (the file
// is static — refreshed only by an image rebuild).
func loadServers() ([]Server, error) {
	serverCacheMu.RLock()
	if len(serverCache) > 0 {
		cached := append([]Server(nil), serverCache...)
		serverCacheMu.RUnlock()
		return cached, nil
	}
	serverCacheMu.RUnlock()

	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()
	if len(serverCache) > 0 {
		return append([]Server(nil), serverCache...), nil
	}

	data, err := os.ReadFile(serversFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", serversFile, err)
	}
	// /v1/api/client/datacenters returns {"0":{...},"5":{...},...}.
	var raw map[string]Server
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", serversFile, err)
	}
	var servers []Server
	for _, s := range raw {
		if s.Slug == "" || s.Country == "" {
			continue
		}
		servers = append(servers, s)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no OVPN datacenters in %s", serversFile)
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Slug < servers[j].Slug })
	serverCache = servers
	shared.Debugf("OVPN: loaded %d datacenters from %s", len(servers), serversFile)
	return append([]Server(nil), servers...), nil
}

// findServers filters by country name/code or city, case-insensitive.
func findServers(servers []Server, location string) []Server {
	if location == "" {
		return servers
	}
	want := strings.ToLower(location)
	var matches []Server
	for _, s := range servers {
		if strings.ToLower(s.Country) == want || strings.ToLower(s.City) == want {
			matches = append(matches, s)
		}
	}
	return matches
}

func pickRandomServer(servers []Server) *Server {
	if len(servers) == 0 {
		return nil
	}
	s := servers[rand.Intn(len(servers))]
	return &s
}

func writeCredentials(user, pass string) (string, error) {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(configDir, credentialsName)
	if err := os.WriteFile(path, []byte(user+"\n"+pass+"\n"), 0600); err != nil {
		return "", err
	}
	return path, nil
}

// writeConfig builds the .ovpn from OVPN's directives (taken verbatim from
// a downloaded config) with the embedded CA + tls-auth and the chosen
// server's two UDP remotes (1194/1195, remote-random).
func writeConfig(server *Server, credFile string) (string, error) {
	host := server.hostname()
	config := fmt.Sprintf(`client
dev tun
tls-version-min 1.0
cipher CHACHA20-POLY1305
data-ciphers CHACHA20-POLY1305:AES-256-GCM:AES-256-CBC:AES-128-GCM
pull
nobind
reneg-sec 0
resolv-retry infinite
verb 3
persist-key
persist-tun
remote-random
remote %s 1194
remote %s 1195
proto udp
mute-replay-warnings
replay-window 256
allow-compression asym
auth-user-pass %s
key-direction 1
<ca>
%s</ca>
<tls-auth>
%s</tls-auth>
`, host, host, credFile, embeddedCACert, embeddedTLSAuth)

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(configDir, activeConfigName)
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	return path, nil
}

// isOpenVPNConnected returns true once the redirect-gateway push has taken
// effect — a route lookup for an arbitrary public address resolves via
// tun0, not eth0. The looser "any tun0 route exists" check trips too early
// (before the default-eclipsing routes), false-positiving the exit-IP
// contract probe. Same gate as cyberghost / ipvanish. Runs in the MAIN
// namespace (openvpn is launched via RunCmd, the main-ns default).
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev tun0 ")
}

func (o OVPN) ActiveLocation(ctx context.Context) string {
	if activeServer == nil {
		return ""
	}
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (o OVPN) Connect(ctx context.Context, location string) provider.Status {
	user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("OVPN: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	servers, err := loadServers()
	if err != nil {
		shared.Debugf("OVPN: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	matches := findServers(servers, location)
	if len(matches) == 0 {
		shared.Debugf("OVPN: no servers for location: %s", location)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	server := pickRandomServer(matches)

	credFile, err := writeCredentials(user, pass)
	if err != nil {
		shared.Debugf("OVPN: write credentials: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	if _, err := writeConfig(server, credFile); err != nil {
		shared.Debugf("OVPN: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	// RunCmd (main ns, NOT a netns variant) so openvpn + tun0 land in the
	// pod's MAIN namespace where the in-process CONNECT proxy lives — the
	// proxy dials with a plain net.DialTimeout (no fwmark), so tun0 must be
	// the main-ns default route. --tun-mtu/--mssfix clamp packet size below
	// the k8s pod MTU so the TLS handshake's UDP packets aren't dropped
	// (same values ipvanish uses).
	if _, err := shared.RunCmd(ctx, "openvpn",
		"--cd", configDir,
		"--config", activeConfigName,
		"--tun-mtu", "1320",
		"--mssfix", "1280",
		"--daemon"); err != nil {
		shared.Debugf("OVPN: failed to start openvpn: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		if isOpenVPNConnected() {
			activeServer = server
			activeMu.Lock()
			activeLocation = location
			activeMu.Unlock()
			return o.Status(ctx)
		}
	}
	shared.Debugf("OVPN: connection timeout for %s", server.hostname())
	return provider.Status{Connected: false, Provider: name, Location: location}
}

func (o OVPN) Connected(ctx context.Context) bool { return isOpenVPNConnected() }

func (o OVPN) Disconnect(ctx context.Context) error {
	_, _ = shared.RunCmd(ctx, "pkill", "-SIGTERM", "openvpn")
	for i := 0; i < 20; i++ {
		if !isOpenVPNConnected() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	activeServer = nil
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
	return nil
}

func (o OVPN) Locations(ctx context.Context) []string {
	servers, err := loadServers()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var locations []string
	for _, s := range servers {
		if s.Country == "" || seen[s.Country] {
			continue
		}
		seen[s.Country] = true
		locations = append(locations, s.Country)
	}
	sort.Strings(locations)
	return locations
}

func (o OVPN) LoggedIn(ctx context.Context) bool { return loggedIn }

func (o OVPN) Login(ctx context.Context) error {
	if _, _, err := getCredentials(); err != nil {
		return err
	}
	if _, err := loadServers(); err != nil {
		return err
	}
	loggedIn = true
	return nil
}

func (o OVPN) Logout(ctx context.Context) error {
	loggedIn = false
	return nil
}

func (o OVPN) Status(ctx context.Context) provider.Status {
	if !isOpenVPNConnected() {
		return provider.Status{Connected: false, Provider: name}
	}
	status := provider.Status{
		Connected: true,
		Location:  o.ActiveLocation(ctx),
		Region:    activeRegion(),
		Provider:  name,
	}
	if out, err := shared.RunCmd(ctx, "curl", "-s", "--max-time", "5", "https://icanhazip.com"); err == nil {
		status.IP = strings.TrimSpace(out)
	}
	return status
}

func activeRegion() string {
	if activeServer == nil {
		return ""
	}
	if activeServer.City != "" {
		return activeServer.Country + " - " + activeServer.City
	}
	return activeServer.Country
}

func (o OVPN) Version(ctx context.Context) (string, error) {
	servers, err := loadServers()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("openvpn (%d datacenters)", len(servers)), nil
}
