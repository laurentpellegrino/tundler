package protonvpn

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	name             = "protonvpn"
	defaultProtocol  = "udp"
	defaultConfigDir = "/etc/protonvpn/openvpn"
)

// embeddedServers is the ProtonVPN server catalog, refreshed daily
// by the proton-updater workflow (see cmd/proton-updater/ and
// .github/workflows/update-proton-servers.yml) and baked into the
// binary at build time so the tunnel pod never has to touch the
// ProtonVPN account API at runtime. var (not const) so tests can
// override it via useTestServers.
//
//go:embed servers.json
var embeddedServers []byte

type ProtonVPN struct{}

type protonServer struct {
	VPN        string   `json:"vpn"`
	Country    string   `json:"country"`
	Region     string   `json:"region"`
	City       string   `json:"city"`
	ServerName string   `json:"server_name"`
	Hostname   string   `json:"hostname"`
	TCP        bool     `json:"tcp"`
	UDP        bool     `json:"udp"`
	IPs        []string `json:"ips"`
	// Features is the Proton API bitfield: 1=SecureCore, 2=Tor,
	// 4=P2P, 8=Stream. Used by the PROTON_FEATURE_FILTER env to
	// restrict the connect-time pool to a subset of tiers.
	Features int `json:"features"`
	Tier     int `json:"tier"`
}

// Feature-bit constants. Mirror the proton-updater main.go layout.
const (
	featureSecureCore = 1
	featureTor        = 2
	featureP2P        = 4
	featureStream     = 8
)

type serversFile struct {
	ProtonVPN struct {
		Servers []protonServer `json:"servers"`
	} `json:"protonvpn"`
}

var (
	// serverCache holds the protocol-filtered subset of embeddedServers,
	// built once on first access (via initServers). Stays valid for the
	// process lifetime — the catalog only refreshes when a new image is
	// rolled out, so there's no reason to invalidate at runtime.
	serverCache    []protonServer
	serverCacheMu  sync.Mutex
	serverCacheErr error
	serverCacheOK  bool

	activeServer   *protonServer
	activeLocation string
	activeMu       sync.RWMutex
	loggedIn       bool
)

func init() { provider.Registry[name] = ProtonVPN{} }

func getCredentials() (string, string, error) {
	user := os.Getenv("PROTON_OPENVPN_USERNAME")
	pass := os.Getenv("PROTON_OPENVPN_PASSWORD")
	if user == "" || pass == "" {
		return "", "", fmt.Errorf("PROTON_OPENVPN_USERNAME and PROTON_OPENVPN_PASSWORD environment variables must be set")
	}
	return user, pass, nil
}

func getProtocol() string {
	proto := strings.ToLower(os.Getenv("PROTON_OPENVPN_PROTOCOL"))
	if proto == "" {
		return defaultProtocol
	}
	if proto != "udp" && proto != "tcp" {
		return defaultProtocol
	}
	return proto
}

func getPort(protocol string) string {
	if port := os.Getenv("PROTON_OPENVPN_PORT"); port != "" {
		if _, err := strconv.Atoi(port); err == nil {
			return port
		}
	}
	if protocol == "tcp" {
		return "443"
	}
	return "1194"
}

func configDir() string {
	if dir := os.Getenv("PROTON_OPENVPN_CONFIG_DIR"); dir != "" {
		return dir
	}
	return defaultConfigDir
}

// requiredFeatureMask reads PROTON_FEATURE_FILTER (CSV of feature
// names: securecore, tor, p2p, stream) and ORs the corresponding
// bits. A server is kept iff every bit in this mask is also set on
// its Features field. Returns 0 (no filter) when the env var is
// empty or unset.
//
// Used to restrict the connect-time pool to a subset of Proton's
// tiers. The motivating case: ipinfo.io blanket-blocks Proton's
// commodity OpenVPN exit IPs (which live in ~10 dense /16s); Proton
// SecureCore exits route through Proton-owned datacenters in IS/SE/
// CH and use a separate, smaller IP pool that may not be on the
// same blocklist. Operators flip this via the StatefulSet env spec
// without a code change.
func requiredFeatureMask() int {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("PROTON_FEATURE_FILTER")))
	if raw == "" {
		return 0
	}
	mask := 0
	for _, name := range strings.Split(raw, ",") {
		switch strings.TrimSpace(name) {
		case "securecore", "secure-core", "secure_core":
			mask |= featureSecureCore
		case "tor":
			mask |= featureTor
		case "p2p":
			mask |= featureP2P
		case "stream":
			mask |= featureStream
		default:
			shared.Debugf("ProtonVPN: PROTON_FEATURE_FILTER token %q not recognized; ignoring", name)
		}
	}
	return mask
}

// fetchServers returns the protocol-filtered ProtonVPN OpenVPN server
// list from the embedded catalog. Result is cached for the process
// lifetime — there's nothing dynamic to invalidate at runtime, the
// catalog only changes when a fresh image rolls out. ctx accepted for
// API symmetry with the previous HTTP-fetching version; not used.
func fetchServers(_ context.Context) ([]protonServer, error) {
	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()

	if serverCacheOK {
		return append([]protonServer(nil), serverCache...), serverCacheErr
	}
	serverCacheOK = true

	var parsed serversFile
	if err := json.Unmarshal(embeddedServers, &parsed); err != nil {
		serverCacheErr = fmt.Errorf("failed to parse embedded ProtonVPN server metadata: %w", err)
		return nil, serverCacheErr
	}

	proto := getProtocol()
	requiredMask := requiredFeatureMask()
	servers := make([]protonServer, 0, len(parsed.ProtonVPN.Servers))
	for _, srv := range parsed.ProtonVPN.Servers {
		if srv.VPN != "openvpn" || srv.Hostname == "" {
			continue
		}
		if requiredMask != 0 && srv.Features&requiredMask != requiredMask {
			continue
		}
		if proto == "udp" && !srv.UDP {
			continue
		}
		if proto == "tcp" && !srv.TCP {
			continue
		}
		servers = append(servers, srv)
	}
	if len(servers) == 0 {
		serverCacheErr = fmt.Errorf("no ProtonVPN OpenVPN servers found in embedded catalog (size=%d bytes)", len(embeddedServers))
		return nil, serverCacheErr
	}
	serverCache = servers
	if requiredMask != 0 {
		shared.Debugf("ProtonVPN: loaded %d OpenVPN servers from embedded catalog (feature filter mask=%d)", len(servers), requiredMask)
	} else {
		shared.Debugf("ProtonVPN: loaded %d OpenVPN servers from embedded catalog", len(servers))
	}
	return append([]protonServer(nil), serverCache...), nil
}

func findServers(servers []protonServer, location string) []protonServer {
	if location == "" {
		return servers
	}

	want := strings.ToLower(location)
	var matches []protonServer
	for _, srv := range servers {
		fields := []string{srv.Country, srv.Region, srv.City, srv.ServerName, srv.Hostname}
		for _, field := range fields {
			if strings.ToLower(field) == want {
				matches = append(matches, srv)
				break
			}
		}
	}
	return matches
}

func pickRandomServer(servers []protonServer) *protonServer {
	if len(servers) == 0 {
		return nil
	}
	server := servers[rand.Intn(len(servers))]
	return &server
}

func isOpenVPNConnected() bool {
	out, err := shared.RunCmd(context.Background(), "ip", "route", "show", "dev", "tun0")
	return err == nil && strings.TrimSpace(out) != ""
}

// ActiveLocation returns whatever was passed to Connect — i.e. an
// entry from Locations(). Reporting the verbatim pool string is what
// makes a config block/allow list match. Granular per-server detail
// (e.g. "Cuba - Havana") is exposed via Status.Region.
func (p ProtonVPN) ActiveLocation(ctx context.Context) string {
	if activeServer == nil {
		return ""
	}
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (p ProtonVPN) Connect(ctx context.Context, location string) provider.Status {
	servers, err := fetchServers(ctx)
	if err != nil {
		shared.Debugf("ProtonVPN: failed to fetch servers: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}

	matches := findServers(servers, location)
	if len(matches) == 0 {
		shared.Debugf("ProtonVPN: no servers found for location: %s", location)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	server := pickRandomServer(matches)
	if err := connectOpenVPN(ctx, server); err != nil {
		shared.Debugf("ProtonVPN: connection failed: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	activeMu.Lock()
	activeLocation = location
	activeMu.Unlock()
	return p.Status(ctx)
}

func connectOpenVPN(ctx context.Context, server *protonServer) error {
	user, pass, err := getCredentials()
	if err != nil {
		return err
	}

	dir := configDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create ProtonVPN config dir: %w", err)
	}

	credentialsFile := filepath.Join(dir, "auth.txt")
	if err := os.WriteFile(credentialsFile, []byte(user+"\n"+pass+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write ProtonVPN credentials: %w", err)
	}

	configFile := filepath.Join(dir, "client.ovpn")
	config := buildOpenVPNConfig(server, credentialsFile)
	if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write ProtonVPN config: %w", err)
	}

	if _, err := shared.RunCmd(ctx, "openvpn", "--config", configFile, "--daemon"); err != nil {
		return fmt.Errorf("failed to start ProtonVPN OpenVPN: %w", err)
	}

	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		if isOpenVPNConnected() {
			activeServer = server
			return nil
		}
	}

	return fmt.Errorf("ProtonVPN OpenVPN connection timeout")
}

func (p ProtonVPN) Connected(ctx context.Context) bool {
	return isOpenVPNConnected()
}

func (p ProtonVPN) Disconnect(ctx context.Context) error {
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

func (p ProtonVPN) Locations(ctx context.Context) []string {
	servers, err := fetchServers(ctx)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var locations []string
	for _, srv := range servers {
		if srv.Country != "" && !seen[srv.Country] {
			seen[srv.Country] = true
			locations = append(locations, srv.Country)
		}
	}
	sort.Strings(locations)
	return locations
}

func (p ProtonVPN) LoggedIn(ctx context.Context) bool {
	return loggedIn
}

func (p ProtonVPN) Login(ctx context.Context) error {
	if _, _, err := getCredentials(); err != nil {
		return err
	}
	if _, err := fetchServers(ctx); err != nil {
		return err
	}
	loggedIn = true
	return nil
}

func (p ProtonVPN) Logout(ctx context.Context) error {
	loggedIn = false
	return nil
}

func (p ProtonVPN) Status(ctx context.Context) provider.Status {
	if !p.Connected(ctx) {
		return provider.Status{Connected: false, Provider: name}
	}

	status := provider.Status{
		Connected: true,
		Location:  p.ActiveLocation(ctx),
		Region:    activeRegion(),
		Provider:  name,
	}
	if ip := publicIP(ctx); ip != "" {
		status.IP = ip
	}
	return status
}

func publicIP(ctx context.Context) string {
	const host = "icanhazip.com"
	resolveIP := ""
	if out, err := shared.RunCmdDirect(ctx, "getent", "ahostsv4", host); err == nil {
		resolveIP = shared.FirstIPv4(out)
	}

	args := []string{"-s", "--max-time", "5"}
	if resolveIP != "" {
		args = append(args, "--resolve", host+":443:"+resolveIP)
	}
	args = append(args, "https://"+host)

	out, err := shared.RunCmd(ctx, "curl", args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func activeRegion() string {
	if activeServer == nil {
		return ""
	}
	if activeServer.City != "" {
		return activeServer.Country + " - " + activeServer.City
	}
	if activeServer.Region != "" {
		return activeServer.Region
	}
	return activeServer.Country
}

func (p ProtonVPN) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, "openvpn", "--version")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0]), nil
}
