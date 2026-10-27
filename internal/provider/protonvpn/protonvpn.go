// Package protonvpn is the ProtonVPN provider: OpenVPN-direct against
// Proton's logical-server catalog (api.proton.me/vpn/v1/logicals,
// mirrored daily by the update-proton-servers workflow into the
// `protonvpn-servers` GitHub release and baked into the image as
// servers.json), with one owned openvpn child per connection supervised
// over a private management socket (internal/shared/ovpn): password
// over the socket, AUTH_FAILED classified as an auth failure, a fixed
// tun interface, at most a couple of servers tried per connect, no
// process leaks.
//
// Proton accepts datacenter source IPs, so there is no outer transport.
// The provider's history is about the crawl target, not connectivity:
// in 2026-05 the crawl target blanket-blocked Proton's commodity exit ranges
// (~10 dense /16s). PROTON_FEATURE_FILTER restricts the pool to a tier
// (securecore, tor, p2p, stream) whose exits live elsewhere.
package protonvpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
	"github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

const (
	name            = "protonvpn"
	defaultProtocol = "udp"
	// defaultServersFile is where docker/providers/protonvpn/install.sh
	// drops the server catalog at image-build time, downloaded from
	// the protonvpn-servers GitHub release. Overridable via
	// PROTON_SERVERS_FILE for local dev.
	defaultServersFile = "/etc/protonvpn/servers.json"
	// defaultRunDir holds the per-connection config and management
	// socket (tmpfs in the image).
	defaultRunDir = "/run/protonvpn"
	// tunnelInterface is the fixed tun name the tunnel comes up on
	// (15 characters is the kernel limit).
	tunnelInterface = "tun-proton"
	// connectTimeout bounds one openvpn attempt: management startup,
	// TLS handshake and the CONNECTED state.
	connectTimeout = 35 * time.Second
	// routeTimeout bounds the wait for the pushed redirect-gateway to
	// become the main-namespace default route after CONNECTED.
	routeTimeout = 10 * time.Second
	// serversPerConnect caps how many servers of a location one Connect
	// tries.
	serversPerConnect = 2
)

// embeddedServers is the ProtonVPN server catalog, loaded lazily from
// defaultServersFile on first fetchServers() call. Kept as a
// package-level var so tests can override it without touching disk.
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

// active is the current connection: the owned openvpn child plus what
// it was asked to connect to.
type active struct {
	tunnel   *ovpn.Tunnel
	server   *protonServer
	location string
}

var (
	// serverCache holds the protocol/feature-filtered subset of
	// embeddedServers, built once on first access. Stays valid for the
	// process lifetime — the catalog only refreshes with a new image.
	serverCache    []protonServer
	serverCacheMu  sync.Mutex
	serverCacheErr error
	serverCacheOK  bool

	activeMu sync.RWMutex
	current  *active

	loggedIn bool
)

func init() {
	provider.Registry[name] = ProtonVPN{}
	accounts.RegisterLegacyShim(name, accounts.LegacyEnvFields(map[string]string{
		accounts.FieldUsername: "PROTON_OPENVPN_USERNAME",
		accounts.FieldPassword: "PROTON_OPENVPN_PASSWORD",
	}))
}

// getCredentials resolves the OpenVPN credential pair (NOT the Proton
// account login — see cmd/proton-updater for that). Protocol/port
// knobs stay plain env: they are config, not credentials.
func getCredentials() (string, string, error) {
	acct, err := accounts.Current(name)
	if err != nil {
		return "", "", err
	}
	user, err := acct.Require(accounts.FieldUsername)
	if err != nil {
		return "", "", err
	}
	pass, err := acct.Require(accounts.FieldPassword)
	if err != nil {
		return "", "", err
	}
	return user, pass, nil
}

func getProtocol() string {
	proto := strings.ToLower(os.Getenv("PROTON_OPENVPN_PROTOCOL"))
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

func runDir() string {
	if dir := os.Getenv("PROTON_RUN_DIR"); dir != "" {
		return dir
	}
	return defaultRunDir
}

// serversFilePath returns the path where install.sh drops the
// downloaded servers.json. Overridable via PROTON_SERVERS_FILE for
// out-of-cluster smoke tests.
func serversFilePath() string {
	if p := os.Getenv("PROTON_SERVERS_FILE"); p != "" {
		return p
	}
	return defaultServersFile
}

func loadEmbeddedServersFromDisk() error {
	if embeddedServers != nil {
		return nil
	}
	data, err := os.ReadFile(serversFilePath())
	if err != nil {
		return fmt.Errorf("read ProtonVPN servers file %s: %w", serversFilePath(), err)
	}
	embeddedServers = data
	return nil
}

// requiredFeatureMask reads PROTON_FEATURE_FILTER (CSV of feature
// names: securecore, tor, p2p, stream) and ORs the corresponding
// bits. A server is kept iff every bit in this mask is also set on
// its Features field. Returns 0 (no filter) when the env var is
// empty or unset.
func requiredFeatureMask() int {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("PROTON_FEATURE_FILTER")))
	if raw == "" {
		return 0
	}
	mask := 0
	for _, token := range strings.Split(raw, ",") {
		switch strings.TrimSpace(token) {
		case "securecore", "secure-core", "secure_core":
			mask |= featureSecureCore
		case "tor":
			mask |= featureTor
		case "p2p":
			mask |= featureP2P
		case "stream":
			mask |= featureStream
		default:
			shared.Debugf("ProtonVPN: PROTON_FEATURE_FILTER token %q not recognized; ignoring", token)
		}
	}
	return mask
}

// fetchServers returns the protocol- and feature-filtered OpenVPN
// server list from the embedded catalog, cached for the process
// lifetime.
func fetchServers(_ context.Context) ([]protonServer, error) {
	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()

	if serverCacheOK {
		return append([]protonServer(nil), serverCache...), serverCacheErr
	}
	serverCacheOK = true

	if err := loadEmbeddedServersFromDisk(); err != nil {
		serverCacheErr = err
		return nil, serverCacheErr
	}

	var parsed serversFile
	if err := json.Unmarshal(embeddedServers, &parsed); err != nil {
		serverCacheErr = fmt.Errorf("failed to parse ProtonVPN server metadata: %w", err)
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
	shared.Debugf("ProtonVPN: loaded %d OpenVPN servers from embedded catalog (feature filter mask=%d)", len(servers), requiredMask)
	return append([]protonServer(nil), serverCache...), nil
}

func findServers(servers []protonServer, location string) []protonServer {
	if location == "" {
		return servers
	}
	want := strings.ToLower(location)
	var matches []protonServer
	for _, srv := range servers {
		for _, field := range []string{srv.Country, srv.Region, srv.City, srv.ServerName, srv.Hostname} {
			if strings.ToLower(field) == want {
				matches = append(matches, srv)
				break
			}
		}
	}
	return matches
}

// isOpenVPNConnected reports whether the tunnel is the path packets
// take RIGHT NOW: a route lookup for a public address resolves via the
// tunnel interface. The looser "the interface exists" check is true too
// early (openvpn adds the link-local route before the redirect-gateway
// routes), which would trip the exit-IP contract probe on a leak that
// does not exist. Main namespace: openvpn runs there.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev "+tunnelInterface+" ")
}

// waitForRoute waits for the pushed default route to land.
func waitForRoute(ctx context.Context, tunnel *ovpn.Tunnel) bool {
	deadline := time.Now().Add(routeTimeout)
	for time.Now().Before(deadline) && ctx.Err() == nil && tunnel.Address() != "" {
		if isOpenVPNConnected() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// ActiveLocation returns whatever was passed to Connect — i.e. an
// entry from Locations(). Reporting the verbatim pool string is what
// makes a config block/allow list match. Granular per-server detail
// (e.g. "CU - Havana") is exposed via Status.Region.
func (p ProtonVPN) ActiveLocation(ctx context.Context) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil {
		return ""
	}
	return current.location
}

func (p ProtonVPN) Connect(ctx context.Context, location string) provider.Status {
	failed := provider.Status{Connected: false, Provider: name, Location: location}
	user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("ProtonVPN: %v", err)
		return failed
	}
	servers, err := fetchServers(ctx)
	if err != nil {
		shared.Debugf("ProtonVPN: failed to fetch servers: %v", err)
		return failed
	}
	matches := findServers(servers, location)
	if len(matches) == 0 {
		shared.Debugf("ProtonVPN: no servers found for location: %s", location)
		return failed
	}

	// One tunnel at a time: drop whatever we own before dialing.
	disconnect(ctx)

	rand.Shuffle(len(matches), func(a, b int) { matches[a], matches[b] = matches[b], matches[a] })
	for idx := range matches {
		if idx >= serversPerConnect || ctx.Err() != nil {
			break
		}
		server := &matches[idx]
		tunnel, err := ovpn.Start(ctx, ovpn.Options{Name: "ProtonVPN", RunDir: runDir(), User: user, Pass: pass, Timeout: connectTimeout},
			func(socket string) ([]byte, error) { return buildOpenVPNConfig(server, socket) })
		if errors.Is(err, ovpn.ErrAuthFailed) {
			// Account-wide: another server cannot help. Report it so
			// the runtime holds instead of re-logging in.
			shared.Debugf("ProtonVPN: %s: %v", server.ServerName, err)
			failed.AuthFailed = true
			return failed
		}
		if err != nil {
			shared.Debugf("ProtonVPN: %s: %v", server.ServerName, err)
			continue
		}
		if !waitForRoute(ctx, tunnel) {
			shared.Debugf("ProtonVPN: %s: connected but the default route never moved to %s", server.ServerName, tunnelInterface)
			stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
			_ = tunnel.Stop(stopCtx)
			cancel()
			continue
		}
		activeMu.Lock()
		current = &active{tunnel: tunnel, server: server, location: location}
		activeMu.Unlock()
		return p.Status(ctx)
	}
	return failed
}

func (p ProtonVPN) Connected(ctx context.Context) bool {
	activeMu.RLock()
	a := current
	activeMu.RUnlock()
	return a != nil && a.tunnel.Address() != "" && isOpenVPNConnected()
}

// disconnect stops the owned tunnel, if any, and forgets it.
func disconnect(ctx context.Context) {
	activeMu.Lock()
	a := current
	current = nil
	activeMu.Unlock()
	if a == nil {
		return
	}
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
	defer cancel()
	if err := a.tunnel.Stop(stopCtx); err != nil {
		shared.Debugf("ProtonVPN: %v", err)
	}
}

func (p ProtonVPN) Disconnect(ctx context.Context) error {
	disconnect(ctx)
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

func (p ProtonVPN) LoggedIn(ctx context.Context) bool { return loggedIn }

// Login only checks that credentials and the catalog are present:
// every connect authenticates on its own.
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
	if out, err := shared.RunCmd(ctx, "getent", "ahostsv4", host); err == nil {
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
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil || current.server == nil {
		return ""
	}
	s := current.server
	if s.City != "" {
		return s.Country + " - " + s.City
	}
	if s.Region != "" {
		return s.Region
	}
	return s.Country
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
