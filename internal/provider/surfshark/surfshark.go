package surfshark

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
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
	Country        string  `json:"country"`
	CountryCode    string  `json:"countryCode"`
	Region         string  `json:"region"`
	Location       string  `json:"location"`
	ConnectionName string  `json:"connectionName"`
	PubKey         string  `json:"pubKey"`
	Load           int     `json:"load"`
}

type WireGuardKey struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

var (
	serverCache     []Server
	serverCacheMu   sync.RWMutex
	serverCacheTime time.Time
	activeServer    *Server
	activeProtocol  string
	loggedIn        bool
)

func init() { provider.Registry[name] = Surfshark{} }

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

// findServers filters servers by ISO country code (e.g., "FR", "US", "DE")
func findServers(servers []Server, location string) []Server {
	if location == "" {
		return servers
	}

	loc := strings.ToUpper(location)
	var matches []Server

	for _, s := range servers {
		if strings.ToUpper(s.CountryCode) == loc {
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

// getWireGuardKeys returns the pool of WireGuard keys
func getWireGuardKeys() ([]WireGuardKey, error) {
	keysJSON := os.Getenv("SURFSHARK_WIREGUARD_KEYS")
	if keysJSON == "" {
		return nil, fmt.Errorf("SURFSHARK_WIREGUARD_KEYS required for WireGuard")
	}

	var keys []WireGuardKey
	if err := json.Unmarshal([]byte(keysJSON), &keys); err != nil {
		return nil, fmt.Errorf("invalid SURFSHARK_WIREGUARD_KEYS JSON: %w", err)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("SURFSHARK_WIREGUARD_KEYS is empty")
	}

	return keys, nil
}

// pickRandomKey selects a random WireGuard key from the pool
func pickRandomKey(keys []WireGuardKey) WireGuardKey {
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
	config := fmt.Sprintf(`client
dev tun
proto udp
remote %s 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass %s
cipher AES-256-CBC
auth SHA512
verb 3
ca /etc/surfshark/ca.crt
tls-auth /etc/surfshark/ta.key 1
`, server.ConnectionName, credFile)

	configFile := "/etc/surfshark/openvpn/client.ovpn"
	if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Start OpenVPN in background
	cmd := exec.CommandContext(ctx, "openvpn", "--config", configFile, "--daemon")
	if err := cmd.Run(); err != nil {
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

	key := pickRandomKey(keys)

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
`, key.Private, server.PubKey, server.ConnectionName)

	configFile := "/etc/surfshark/wireguard/wg0.conf"
	if err := os.WriteFile(configFile, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Start WireGuard
	cmd := exec.CommandContext(ctx, "wg-quick", "up", configFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start wireguard: %w: %s", err, output)
	}

	activeServer = server
	activeProtocol = "wireguard"
	return nil
}

// isOpenVPNConnected checks if OpenVPN tunnel is up
func isOpenVPNConnected() bool {
	out, err := exec.Command("ip", "link", "show", "tun0").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "UP")
}

// isWireGuardConnected checks if WireGuard tunnel is up
func isWireGuardConnected() bool {
	out, err := exec.Command("wg", "show", "wg0").Output()
	if err != nil {
		return false
	}
	return len(out) > 0
}

func (s Surfshark) ActiveLocation(ctx context.Context) string {
	if activeServer != nil {
		return fmt.Sprintf("%s - %s", activeServer.Country, activeServer.Location)
	}
	return ""
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
		exec.Command("wg-quick", "down", "/etc/surfshark/wireguard/wg0.conf").Run()
	} else {
		exec.Command("pkill", "-SIGTERM", "openvpn").Run()
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
		code := strings.ToUpper(srv.CountryCode)
		if !seen[code] {
			seen[code] = true
			locations = append(locations, code)
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
			return fmt.Errorf("SURFSHARK_WIREGUARD_KEYS not configured")
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
		Provider:  name,
	}

	// Get VPN IP (quick timeout)
	if out, err := exec.Command("curl", "-s", "--max-time", "2", "https://api.ipify.org").Output(); err == nil {
		status.IP = strings.TrimSpace(string(out))
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
