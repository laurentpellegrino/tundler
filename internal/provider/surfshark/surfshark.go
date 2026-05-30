package surfshark

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const name = "surfshark"
const apiURL = "https://api.surfshark.com/v4/server/clusters/generic"
const cacheExpiry = 1 * time.Hour

type Surfshark struct{}

type Server struct {
	Country        string `json:"country"`
	CountryCode    string `json:"countryCode"`
	Region         string `json:"region"`
	Location       string `json:"location"`
	ConnectionName string `json:"connectionName"`
	PubKey         string `json:"pubKey"`
	Load           int    `json:"load"`
}

var (
	serverCache     []Server
	serverCacheMu   sync.RWMutex
	serverCacheTime time.Time
	activeServer    *Server
	activeProtocol  string
	activeLocation  string
	activeMu        sync.RWMutex
	loggedIn        bool
)

func init() { provider.Registry[name] = Surfshark{} }

func activeRegion() string {
	if activeServer == nil {
		return ""
	}
	if activeServer.Location != "" {
		return fmt.Sprintf("%s - %s", activeServer.Country, activeServer.Location)
	}
	if activeServer.Region != "" {
		return activeServer.Region
	}
	return activeServer.Country
}

// fetchServers retrieves server list from API or cache
func fetchServers(ctx context.Context) ([]Server, error) {
	serverCacheMu.RLock()
	if len(serverCache) > 0 && time.Since(serverCacheTime) < cacheExpiry {
		servers := serverCache
		serverCacheMu.RUnlock()
		return servers, nil
	}
	serverCacheMu.RUnlock()

	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()

	// Double-check after acquiring write lock
	if len(serverCache) > 0 && time.Since(serverCacheTime) < cacheExpiry {
		return serverCache, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var servers []Server
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		return nil, err
	}

	serverCache = servers
	serverCacheTime = time.Now()
	shared.Debugf("Surfshark: cached %d servers", len(servers))

	return servers, nil
}

// findServers filters servers by country name (e.g., "France", "United States", "Germany")
func findServers(servers []Server, location string) []Server {
	if location == "" {
		return servers
	}

	loc := strings.ToLower(location)
	var matches []Server

	for _, s := range servers {
		if strings.ToLower(s.Country) == loc {
			matches = append(matches, s)
		}
	}

	return matches
}

// pickRandomServer selects a random server from the list
func pickRandomServer(servers []Server) *Server {
	if len(servers) == 0 {
		return nil
	}
	return &servers[rand.Intn(len(servers))]
}

// getProtocol returns the configured protocol (openvpn or wireguard)
func getProtocol() string {
	proto := os.Getenv("SURFSHARK_PROTOCOL")
	if proto == "" {
		proto = "openvpn"
	}
	return strings.ToLower(proto)
}

// getOpenVPNCredentials returns OpenVPN username and password
func getOpenVPNCredentials() (string, string, error) {
	user := os.Getenv("SURFSHARK_OPENVPN_USERNAME")
	pass := os.Getenv("SURFSHARK_OPENVPN_PASSWORD")
	if user == "" || pass == "" {
		return "", "", fmt.Errorf("SURFSHARK_OPENVPN_USERNAME and SURFSHARK_OPENVPN_PASSWORD required for OpenVPN")
	}
	return user, pass, nil
}

// getWireGuardKeys returns the pool of WireGuard private keys
func getWireGuardKeys() ([]string, error) {
	keysStr := os.Getenv("SURFSHARK_WIREGUARD_PRIVATE_KEYS")
	if keysStr == "" {
		return nil, fmt.Errorf("SURFSHARK_WIREGUARD_PRIVATE_KEYS required for WireGuard")
	}

	var keys []string
	for _, k := range strings.Split(keysStr, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			keys = append(keys, k)
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("SURFSHARK_WIREGUARD_PRIVATE_KEYS is empty")
	}

	return keys, nil
}

// pickRandomKey selects a random WireGuard private key from the pool
func pickRandomKey(keys []string) string {
	return keys[rand.Intn(len(keys))]
}

// connectOpenVPN connects using OpenVPN
func connectOpenVPN(ctx context.Context, server *Server) error {
	user, pass, err := getOpenVPNCredentials()
	if err != nil {
		return err
	}

	// Write credentials file
	credFile := "/etc/surfshark/openvpn/auth.txt"
	if err := os.WriteFile(credFile, []byte(user+"\n"+pass+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}

	// Generate OpenVPN config
	// Use UDP to avoid TCP-over-TCP meltdown (retransmission cascades
	// causing TLS handshake timeouts under high concurrency)
	config := fmt.Sprintf(`client
dev tun
proto udp
remote %s 1194
remote-random
nobind
tun-mtu 1500
mssfix 1450
ping 15
ping-restart 0
reneg-sec 0
remote-cert-tls server
auth-user-pass %s
cipher AES-256-CBC
auth SHA512
fast-io
verb 3
ca /etc/surfshark/ca.crt
tls-auth /etc/surfshark/ta.key 1
`, server.ConnectionName, credFile)

	configFile := "/etc/surfshark/openvpn/client.ovpn"
	if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Start OpenVPN in background inside VPN namespace
	// RunCmd waits for the parent to exit (--daemon forks to background)
	if _, err := shared.RunCmd(ctx, "openvpn", "--config", configFile, "--daemon"); err != nil {
		return fmt.Errorf("failed to start openvpn: %w", err)
	}

	// Wait for connection (check every 500ms, max 15 seconds)
	for i := 0; i < 30; i++ {
		time.Sleep(500 * time.Millisecond)
		if isOpenVPNConnected() {
			activeServer = server
			activeProtocol = "openvpn"
			return nil
		}
	}

	return fmt.Errorf("openvpn connection timeout")
}

// connectWireGuard connects using WireGuard
func connectWireGuard(ctx context.Context, server *Server) error {
	keys, err := getWireGuardKeys()
	if err != nil {
		return err
	}

	privateKey := pickRandomKey(keys)

	// Generate WireGuard config
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.14.0.2/16
DNS = 162.252.172.57, 149.154.159.92

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s:51820
PersistentKeepalive = 25
`, privateKey, server.PubKey, server.ConnectionName)

	configFile := "/etc/surfshark/wireguard/wg0.conf"
	if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Bring wg0 up in the MAIN network namespace (NOT vpnns).
	// The in-process CONNECT proxy lives in main ns and dials
	// upstream with a plain net.DialTimeout — no fwmark — so for
	// proxy traffic to traverse the tunnel, wg0 has to be the
	// main-ns default route. wg-quick's "suppress_prefixlength 0"
	// + "not fwmark 51820 lookup 51820" rules make wg0 the de-facto
	// main-ns default while keeping cluster CIDR (covered by the
	// onlink 10.0.0.0/16 route installed at entrypoint) on eth0.
	// This is the same model OpenVPN-daemon providers use
	// (tun0 lives in main ns because the daemon does too).
	// RunCmd (the new default after the 2026-05-28 inversion) skips the `ip netns exec vpnns` wrap that
	// systemd-Environment TUNDLER_NETNS=vpnns would otherwise add.
	//
	// Idempotency guard: tundler-tunnel.service restarts inside the SAME
	// pod (and thus the same network namespace) on failure, so a wg0
	// brought up by a previous attempt survives the restart. Without a
	// clean Disconnect in between (a crash, or a connect that failed the
	// exit-IP contract after `up`), the next `wg-quick up` aborts with
	// "`wg0' already exists" and the pod crashloops forever with no path
	// to recovery. Tear down any leftover wg0 first — best-effort, errors
	// ignored since on the happy path there's nothing to remove.
	cleanupStaleWireGuard(ctx, configFile)

	output, err := shared.RunCmd(ctx, "wg-quick", "up", configFile)
	if err != nil {
		return fmt.Errorf("failed to start wireguard: %w: %s", err, output)
	}

	activeServer = server
	activeProtocol = "wireguard"
	return nil
}

// cleanupStaleWireGuard best-effort removes a leftover wg0 interface
// before a fresh `wg-quick up`. See the call site in connectWireGuard
// for why a stale wg0 can survive into a new connect attempt. No-op
// when wg0 isn't present (the happy path); all errors are ignored.
func cleanupStaleWireGuard(ctx context.Context, configFile string) {
	if !wireGuardInterfacePresent(ctx) {
		return
	}
	shared.Debugf("Surfshark: stale wg0 from a prior run — tearing down before up")
	// wg-quick down unwinds the routes/rules/fwmark it installed; the
	// bare `ip link del` is a fallback for when only the interface is
	// left (e.g. wg-quick down can't find its saved state).
	shared.RunCmdSilent(ctx, "wg-quick", "down", configFile)
	shared.RunCmdSilent(ctx, "ip", "link", "del", "wg0")
}

// wireGuardInterfacePresent reports whether a wg0 link exists in the
// current (main) network namespace.
func wireGuardInterfacePresent(ctx context.Context) bool {
	_, err := shared.RunCmdSilent(ctx, "ip", "link", "show", "wg0")
	return err == nil
}

// isOpenVPNConnected returns true once the tunnel's redirect-gateway
// push has actually taken effect — i.e. the kernel's route lookup
// for an arbitrary public address resolves via tun0, not via eth0.
// The looser "any route on tun0 exists" check returns true too
// early: openvpn installs the per-pod link-local route (e.g.
// 10.x.0.0/24 dev tun0) BEFORE the redirect-gateway default-
// eclipsing routes are pushed, so the exit-IP contract probe in
// cmd/tundler-tunnel/egress.go fires while the main-ns default
// route is still via eth0 and flags a false-positive leak.
// Validated against cyberghost — same race, same fix.
//
// Production currently runs Surfshark in WireGuard mode (see
// SURFSHARK_PROTOCOL env), so this OpenVPN branch isn't exercised
// today; keeping the fix in place so a future protocol flip doesn't
// regress on the contract test.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev tun0 ")
}

// isWireGuardConnected checks if WireGuard tunnel is up in the main
// network namespace. Connect() now brings wg0 up in main ns (see the
// comment in connectWireGuard) so the check must look there too —
// `wg show wg0` via RunCmd would `ip netns exec vpnns` into the wrong
// namespace and report the tunnel as down.
func isWireGuardConnected() bool {
	out, err := shared.RunCmd(context.Background(), "wg", "show", "wg0")
	if err != nil {
		return false
	}
	return len(out) > 0
}

// ActiveLocation returns whatever was passed to Connect — i.e. an
// entry from Locations(). Reporting the verbatim pool string is what
// makes a config block/allow list match. Granular per-server detail
// (e.g. "United States - New York") is exposed via Status.Region.
func (s Surfshark) ActiveLocation(ctx context.Context) string {
	if activeServer == nil {
		return ""
	}
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (s Surfshark) Connect(ctx context.Context, location string) provider.Status {
	servers, err := fetchServers(ctx)
	if err != nil {
		shared.Debugf("Surfshark: failed to fetch servers: %v", err)
		return provider.Status{Connected: false}
	}

	matches := findServers(servers, location)
	if len(matches) == 0 {
		shared.Debugf("Surfshark: no servers found for location: %s", location)
		return provider.Status{Connected: false}
	}

	server := pickRandomServer(matches)
	shared.Debugf("Surfshark: connecting to %s (%s)", server.ConnectionName, server.Country)

	proto := getProtocol()
	var connectErr error

	if proto == "wireguard" {
		connectErr = connectWireGuard(ctx, server)
	} else {
		connectErr = connectOpenVPN(ctx, server)
	}

	if connectErr != nil {
		shared.Debugf("Surfshark: connection failed: %v", connectErr)
		return provider.Status{Connected: false}
	}
	activeMu.Lock()
	activeLocation = location
	activeMu.Unlock()
	return s.Status(ctx)
}

func (s Surfshark) Connected(ctx context.Context) bool {
	proto := getProtocol()
	if proto == "wireguard" {
		return isWireGuardConnected()
	}
	return isOpenVPNConnected()
}

func (s Surfshark) Disconnect(ctx context.Context) error {
	proto := activeProtocol
	if proto == "" {
		proto = getProtocol()
	}

	if proto == "wireguard" {
		// wg-quick down has to run in the same namespace where
		// `up` ran (main ns — see connectWireGuard); otherwise it
		// no-ops against an empty vpnns and leaks wg0 + the
		// associated policy-routing rules across rotations.
		shared.RunCmd(ctx, "wg-quick", "down", "/etc/surfshark/wireguard/wg0.conf")
	} else {
		shared.RunCmd(ctx, "pkill", "-SIGTERM", "openvpn")
		// Wait for process to terminate
		for i := 0; i < 10; i++ {
			if !isOpenVPNConnected() {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	activeServer = nil
	activeProtocol = ""
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
	return nil
}

func (s Surfshark) Locations(ctx context.Context) []string {
	servers, err := fetchServers(ctx)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var locations []string

	for _, srv := range servers {
		if !seen[srv.Country] {
			seen[srv.Country] = true
			locations = append(locations, srv.Country)
		}
	}

	return locations
}

func (s Surfshark) LoggedIn(ctx context.Context) bool {
	return loggedIn
}

func (s Surfshark) Login(ctx context.Context) error {
	proto := getProtocol()
	if proto == "wireguard" {
		if _, err := getWireGuardKeys(); err != nil {
			return fmt.Errorf("SURFSHARK_WIREGUARD_PRIVATE_KEYS not configured")
		}
	} else {
		if _, _, err := getOpenVPNCredentials(); err != nil {
			return fmt.Errorf("SURFSHARK_OPENVPN_USERNAME and SURFSHARK_OPENVPN_PASSWORD not configured")
		}
	}
	loggedIn = true
	return nil
}

func (s Surfshark) Logout(ctx context.Context) error {
	loggedIn = false
	return nil
}

func (s Surfshark) Status(ctx context.Context) provider.Status {
	if !s.Connected(ctx) {
		return provider.Status{Connected: false, Provider: name}
	}

	status := provider.Status{
		Connected: true,
		Location:  s.ActiveLocation(ctx),
		Region:    activeRegion(),
		Provider:  name,
	}

	// Get VPN IP (quick timeout)
	if out, err := shared.RunCmd(ctx, "curl", "-s", "--max-time", "2", "https://icanhazip.com"); err == nil {
		status.IP = strings.TrimSpace(out)
	}

	return status
}

func (s Surfshark) Version(ctx context.Context) (string, error) {
	servers, err := fetchServers(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("API (%d servers)", len(servers)), nil
}
