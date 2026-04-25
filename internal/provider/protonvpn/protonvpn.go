package protonvpn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
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
	defaultServers   = "/etc/protonvpn/servers.json"
	defaultConfigDir = "/etc/protonvpn/openvpn"
	serversURL       = "https://raw.githubusercontent.com/qdm12/gluetun/master/internal/storage/servers.json"
	cacheExpiry      = 24 * time.Hour
)

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
}

type serversFile struct {
	ProtonVPN struct {
		Servers []protonServer `json:"servers"`
	} `json:"protonvpn"`
}

var (
	serverCache     []protonServer
	serverCacheMu   sync.RWMutex
	serverCacheTime time.Time
	activeServer    *protonServer
	loggedIn        bool
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

func serversPath() string {
	if path := os.Getenv("PROTON_SERVERS_FILE"); path != "" {
		return path
	}
	return defaultServers
}

func configDir() string {
	if dir := os.Getenv("PROTON_OPENVPN_CONFIG_DIR"); dir != "" {
		return dir
	}
	return defaultConfigDir
}

func fetchServers(ctx context.Context) ([]protonServer, error) {
	serverCacheMu.RLock()
	if len(serverCache) > 0 && time.Since(serverCacheTime) < cacheExpiry {
		servers := append([]protonServer(nil), serverCache...)
		serverCacheMu.RUnlock()
		return servers, nil
	}
	serverCacheMu.RUnlock()

	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()

	if len(serverCache) > 0 && time.Since(serverCacheTime) < cacheExpiry {
		return append([]protonServer(nil), serverCache...), nil
	}

	data, err := os.ReadFile(serversPath())
	if err != nil || len(data) == 0 {
		data, err = downloadServers(ctx)
		if err != nil {
			return nil, err
		}
		_ = os.MkdirAll(filepath.Dir(serversPath()), 0755)
		_ = os.WriteFile(serversPath(), data, 0644)
	}

	var parsed serversFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse ProtonVPN server metadata: %w", err)
	}

	var servers []protonServer
	proto := getProtocol()
	for _, srv := range parsed.ProtonVPN.Servers {
		if srv.VPN != "openvpn" || srv.Hostname == "" {
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
		return nil, fmt.Errorf("no ProtonVPN OpenVPN servers found")
	}

	serverCache = servers
	serverCacheTime = time.Now()
	shared.Debugf("ProtonVPN: cached %d OpenVPN servers", len(servers))

	return append([]protonServer(nil), servers...), nil
}

func downloadServers(ctx context.Context) ([]byte, error) {
	url := os.Getenv("PROTON_SERVERS_URL")
	if url == "" {
		url = serversURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download ProtonVPN server metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download ProtonVPN server metadata: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
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

func (p ProtonVPN) ActiveLocation(ctx context.Context) string {
	if activeServer == nil {
		return ""
	}
	if activeServer.City != "" {
		return activeServer.Country + " - " + activeServer.City
	}
	return activeServer.Country
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
