// Package cyberghost is an OpenVPN-direct provider for CyberGhost VPN.
//
// Why OpenVPN-direct (not the official `cyberghostvpn` CLI):
// CyberGhost's Linux CLI requires an INTERACTIVE `cyberghostvpn --setup`
// for credentials, and the binary itself isn't on a public apt repo
// (the .deb is gated behind an authenticated download token in the
// dashboard). Neither maps onto our headless / scripted pod boot.
// We therefore drive openvpn directly against CyberGhost's published
// server hostnames, same model we use for protonvpn / surfshark / the
// retired ipvanish.
//
// Auth model (4-factor, like gluetun's cyberghost integration):
//
//   - client certificate + private key  — per-device, generated via
//     "Configure Device → OpenVPN" in the dashboard
//   - OpenVPN username + password       — per-device, shown on the
//     same dashboard screen as the cert/key download
//   - CyberGhost root CA (ca.crt)       — same for every customer,
//     baked into the binary via go:embed below
//
// Per-pod credential isolation:
// CyberGhost enforces a one-active-session-per-device policy (sustained
// concurrent logins on the same cert/key cause knock-off). The
// StatefulSet bundles all max_tunnels device profiles into a single
// k8s Secret with namespaced keys (POD_0_CERTIFICATE, POD_0_KEY,
// POD_0_USERNAME, POD_0_PASSWORD, POD_1_..., ... POD_N_*). Each pod
// extracts its ordinal from POD_NAME at boot and uses ONLY its own
// quadruple, so 7 pods use 7 distinct device profiles and no two
// pods ever present the same cert/key to CyberGhost's auth backend.
//
// Server-list freshness:
// servers.json is baked at image build time from the cyberghost-servers
// GitHub release (refreshed daily by a workflow that authenticates
// against CyberGhost's dashboard API — see .github/workflows/
// update-cyberghost-servers.yml). If the release stops refreshing,
// the embedded list ages but the runtime keeps working — servers
// rarely churn.
package cyberghost

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	name             = "cyberghost"
	defaultConfigDir = "/etc/cyberghost/openvpn"
	activeConfigName = "active.ovpn"
	credentialsName  = "auth.txt"
	clientCertName   = "client.crt"
	clientKeyName    = "client.key"
	caCertName       = "ca.crt"
)

//go:embed ca.crt
var embeddedCACert []byte

//go:embed servers.json
var embeddedServers []byte

type CyberGhost struct{}

type cyberghostServer struct {
	Country  string `json:"country"`
	City     string `json:"city,omitempty"`
	Hostname string `json:"hostname"`
}

var (
	serverCache    []cyberghostServer
	serverCacheMu  sync.RWMutex
	activeServer   *cyberghostServer
	activeLocation string
	activeMu       sync.RWMutex
	loggedIn       bool

	// Extracts the ordinal suffix from a StatefulSet pod name
	// (e.g. "tundler-tunnel-cyberghost-3" → 3). The provider reads
	// its per-pod credentials from POD_<ordinal>_* env vars.
	podOrdinalRe = regexp.MustCompile(`-(\d+)$`)
)

func init() { provider.Registry[name] = CyberGhost{} }

func configDir() string {
	if dir := os.Getenv("CYBERGHOST_CONFIG_DIR"); dir != "" {
		return dir
	}
	return defaultConfigDir
}

// podOrdinal extracts this pod's ordinal index from POD_NAME (downward
// API). Returns 0 when POD_NAME is unset (local-dev fallback — Login
// still verifies POD_0_* creds exist before declaring success).
func podOrdinal() (int, error) {
	pod := os.Getenv("POD_NAME")
	if pod == "" {
		return 0, nil
	}
	m := podOrdinalRe.FindStringSubmatch(pod)
	if m == nil {
		return 0, fmt.Errorf("POD_NAME=%q has no -N ordinal suffix", pod)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("POD_NAME=%q ordinal parse: %w", pod, err)
	}
	return n, nil
}

// getCredentials returns the per-pod (cert, key, username, password)
// quadruple from env. Each pod ordinal reads POD_<n>_CERTIFICATE,
// POD_<n>_KEY, POD_<n>_USERNAME, POD_<n>_PASSWORD — the ExternalSecret
// renders one k8s Secret holding all max_tunnels quadruples.
func getCredentials() (cert, key, user, pass string, err error) {
	ord, err := podOrdinal()
	if err != nil {
		return "", "", "", "", err
	}
	prefix := fmt.Sprintf("POD_%d_", ord)
	cert = os.Getenv(prefix + "CERTIFICATE")
	key = os.Getenv(prefix + "KEY")
	user = os.Getenv(prefix + "USERNAME")
	pass = os.Getenv(prefix + "PASSWORD")
	if cert == "" || key == "" || user == "" || pass == "" {
		return "", "", "", "", fmt.Errorf(
			"missing CyberGhost credentials for pod ordinal %d "+
				"(need %sCERTIFICATE, %sKEY, %sUSERNAME, %sPASSWORD)",
			ord, prefix, prefix, prefix, prefix)
	}
	return cert, key, user, pass, nil
}

func loadServers() ([]cyberghostServer, error) {
	serverCacheMu.RLock()
	if len(serverCache) > 0 {
		cached := append([]cyberghostServer(nil), serverCache...)
		serverCacheMu.RUnlock()
		return cached, nil
	}
	serverCacheMu.RUnlock()

	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()
	if len(serverCache) > 0 {
		return append([]cyberghostServer(nil), serverCache...), nil
	}

	var servers []cyberghostServer
	if err := json.Unmarshal(embeddedServers, &servers); err != nil {
		return nil, fmt.Errorf("parse embedded servers.json: %w", err)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("embedded servers.json is empty")
	}
	serverCache = servers
	shared.Debugf("CyberGhost: loaded %d embedded servers", len(servers))
	return append([]cyberghostServer(nil), servers...), nil
}

func findServers(servers []cyberghostServer, location string) []cyberghostServer {
	if location == "" {
		return servers
	}
	want := strings.ToLower(location)
	var matches []cyberghostServer
	for _, s := range servers {
		if strings.ToLower(s.Country) == want ||
			strings.ToLower(s.City) == want {
			matches = append(matches, s)
		}
	}
	return matches
}

func pickRandomServer(servers []cyberghostServer) *cyberghostServer {
	if len(servers) == 0 {
		return nil
	}
	s := servers[rand.Intn(len(servers))]
	return &s
}

// writeAuthArtifacts writes the per-pod cert / key / auth file (plus
// the embedded CA) into the config directory at known names. The
// generated .ovpn references them via `ca <file>`, `cert <file>`,
// `key <file>`, `auth-user-pass <file>`. All files are 0600 except
// ca.crt (0644) — the cert+key pair is the per-device secret.
func writeAuthArtifacts(dir, cert, key, user, pass string) (caPath, certPath, keyPath, authPath string, err error) {
	if err = os.MkdirAll(dir, 0700); err != nil {
		return
	}
	caPath = filepath.Join(dir, caCertName)
	if err = os.WriteFile(caPath, embeddedCACert, 0644); err != nil {
		err = fmt.Errorf("write ca.crt: %w", err)
		return
	}
	certPath = filepath.Join(dir, clientCertName)
	if err = os.WriteFile(certPath, []byte(cert), 0600); err != nil {
		err = fmt.Errorf("write client.crt: %w", err)
		return
	}
	keyPath = filepath.Join(dir, clientKeyName)
	if err = os.WriteFile(keyPath, []byte(key), 0600); err != nil {
		err = fmt.Errorf("write client.key: %w", err)
		return
	}
	authPath = filepath.Join(dir, credentialsName)
	if err = os.WriteFile(authPath, []byte(user+"\n"+pass+"\n"), 0600); err != nil {
		err = fmt.Errorf("write auth.txt: %w", err)
		return
	}
	return
}

// buildOpenVPNConfig produces the .ovpn content for one server. Shape
// mirrors the bundle CyberGhost's dashboard generates (extracted from
// a real Configure Device download — same data-ciphers, ping, etc.).
// We strip nothing: their config is already OpenSSL 3 / OpenVPN 2.6
// clean (unlike ipvanish's legacy tls-cipher pinning).
func buildOpenVPNConfig(server *cyberghostServer, caPath, certPath, keyPath, authPath string) string {
	return fmt.Sprintf(`client
remote %s 443
dev tun
proto udp
auth-user-pass %s
resolv-retry infinite
redirect-gateway def1
persist-key
persist-tun
nobind
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC
auth SHA256
ping 5
explicit-exit-notify 2
script-security 2
remote-cert-tls server
route-delay 5
verb 3
ca %s
cert %s
key %s
`, server.Hostname, authPath, caPath, certPath, keyPath)
}

func writeActiveConfig(dir string, server *cyberghostServer, caPath, certPath, keyPath, authPath string) (string, error) {
	dst := filepath.Join(dir, activeConfigName)
	if err := os.WriteFile(dst, []byte(buildOpenVPNConfig(server, caPath, certPath, keyPath, authPath)), 0600); err != nil {
		return "", fmt.Errorf("write active config: %w", err)
	}
	return dst, nil
}

// isOpenVPNConnected returns true once openvpn has finished tunnel
// setup. Looks in MAIN namespace — openvpn is launched there so the
// in-process CONNECT proxy can reach tun0. Silent so the connect-
// poll loop doesn't flood journald with "Cannot find device tun0".
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "show", "dev", "tun0")
	return err == nil && strings.TrimSpace(out) != ""
}

func (c CyberGhost) ActiveLocation(ctx context.Context) string {
	if activeServer == nil {
		return ""
	}
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (c CyberGhost) Connect(ctx context.Context, location string) provider.Status {
	cert, key, user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("CyberGhost: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}

	servers, err := loadServers()
	if err != nil {
		shared.Debugf("CyberGhost: failed to load servers: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}

	matches := findServers(servers, location)
	if len(matches) == 0 {
		shared.Debugf("CyberGhost: no servers found for location: %s", location)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	server := pickRandomServer(matches)
	dir := configDir()
	caPath, certPath, keyPath, authPath, err := writeAuthArtifacts(dir, cert, key, user, pass)
	if err != nil {
		shared.Debugf("CyberGhost: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	if _, err := writeActiveConfig(dir, server, caPath, certPath, keyPath, authPath); err != nil {
		shared.Debugf("CyberGhost: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	// --tun-mtu / --mssfix clamp below the k8s pod MTU (1370 on
	// Talos/Cilium); default 1500-byte payloads get PMTU-dropped on
	// the encapsulated path. RunCmd (the post-bb88d29 default —
	// main netns, not vpnns) so openvpn + tun0 land in the same
	// namespace as the CONNECT proxy.
	if _, err := shared.RunCmd(ctx, "openvpn",
		"--cd", dir,
		"--config", activeConfigName,
		"--tun-mtu", "1320",
		"--mssfix", "1280",
		"--daemon"); err != nil {
		shared.Debugf("CyberGhost: failed to start openvpn: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	for j := 0; j < 60; j++ {
		time.Sleep(500 * time.Millisecond)
		if isOpenVPNConnected() {
			activeServer = server
			activeMu.Lock()
			activeLocation = location
			activeMu.Unlock()
			return c.Status(ctx)
		}
	}

	shared.Debugf("CyberGhost: connection timeout for %s", server.Hostname)
	return provider.Status{Connected: false, Provider: name, Location: location}
}

func (c CyberGhost) Connected(ctx context.Context) bool {
	return isOpenVPNConnected()
}

func (c CyberGhost) Disconnect(ctx context.Context) error {
	_, _ = shared.RunCmd(ctx, "pkill", "-SIGTERM", "openvpn")
	for j := 0; j < 20; j++ {
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

func (c CyberGhost) Locations(ctx context.Context) []string {
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

func (c CyberGhost) LoggedIn(ctx context.Context) bool { return loggedIn }

func (c CyberGhost) Login(ctx context.Context) error {
	if _, _, _, _, err := getCredentials(); err != nil {
		return err
	}
	if _, err := loadServers(); err != nil {
		return err
	}
	loggedIn = true
	return nil
}

func (c CyberGhost) Logout(ctx context.Context) error {
	loggedIn = false
	return nil
}

func (c CyberGhost) Status(ctx context.Context) provider.Status {
	if !c.Connected(ctx) {
		return provider.Status{Connected: false, Provider: name}
	}
	status := provider.Status{
		Connected: true,
		Location:  c.ActiveLocation(ctx),
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
	if activeServer == nil {
		return ""
	}
	if activeServer.City != "" {
		return activeServer.Country + " - " + activeServer.City
	}
	return activeServer.Country
}

func (c CyberGhost) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, "openvpn", "--version")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0]), nil
}
