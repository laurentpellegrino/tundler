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

// embeddedServers is the build-time-baked server list. Used ONLY as a
// fallback when /etc/cyberghost/servers.json (the daily-refresh
// overlay installed by docker/providers/cyberghost/install.sh) is
// missing or unparseable. The on-disk file is the authoritative
// source — it's refreshed daily by .github/workflows/update-
// cyberghost-servers.yml and downloaded fresh at image build, so
// a pod that boots on a 6-month-old image still gets a current
// server list (its image-layer copy).
//
//go:embed servers.json
var embeddedServers []byte

// runtimeServersPath is where install.sh drops the daily-refreshed
// list inside the image. Read at boot by loadServers(); takes
// precedence over embeddedServers when present and parseable.
const runtimeServersPath = "/etc/cyberghost/servers.json"

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

// credsDir is where the StatefulSet projects the vpn-credentials-
// cyberghost Secret as a directory (one file per key). Reading from
// files (not env) sidesteps the entrypoint's printenv|grep filter
// that truncates multi-line PEMs to their first line — see the
// comment in render-vpn-manifests.py next to the cyberghost-creds
// volume for the full history.
const credsDir = "/etc/cyberghost/creds"

// getCredentials returns the per-pod (cert, key, username, password)
// quadruple. Each pod ordinal reads POD_<n>_CERTIFICATE,
// POD_<n>_KEY, POD_<n>_USERNAME, POD_<n>_PASSWORD as separate files
// projected from the Secret at /etc/cyberghost/creds/. username
// and password are trimmed of trailing whitespace; cert and key
// are passed through untouched (PEM is whitespace-sensitive).
func getCredentials() (cert, key, user, pass string, err error) {
	ord, err := podOrdinal()
	if err != nil {
		return "", "", "", "", err
	}
	prefix := fmt.Sprintf("POD_%d_", ord)
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(credsDir, name))
		return string(b), err
	}
	certB, errCert := read(prefix + "CERTIFICATE")
	keyB, errKey := read(prefix + "KEY")
	userB, errUser := read(prefix + "USERNAME")
	passB, errPass := read(prefix + "PASSWORD")
	if errCert != nil || errKey != nil || errUser != nil || errPass != nil {
		return "", "", "", "", fmt.Errorf(
			"missing CyberGhost credentials for pod ordinal %d in %s "+
				"(need %sCERTIFICATE, %sKEY, %sUSERNAME, %sPASSWORD)",
			ord, credsDir, prefix, prefix, prefix, prefix)
	}
	return certB, keyB, strings.TrimSpace(userB), strings.TrimSpace(passB), nil
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

	var (
		servers []cyberghostServer
		source  string
	)
	// Prefer the daily-refreshed overlay if it parses and has
	// content. Any failure (missing file, malformed JSON, empty
	// array) falls through to the embedded fallback rather than
	// crash-looping the pod — a stale image is better than no
	// servers at all.
	if raw, err := os.ReadFile(runtimeServersPath); err == nil {
		if jerr := json.Unmarshal(raw, &servers); jerr == nil && len(servers) > 0 {
			source = runtimeServersPath
		} else if jerr != nil {
			shared.Debugf("CyberGhost: runtime %s unparseable (%v) — falling back to embedded", runtimeServersPath, jerr)
			servers = nil
		}
	}
	if len(servers) == 0 {
		if err := json.Unmarshal(embeddedServers, &servers); err != nil {
			return nil, fmt.Errorf("parse embedded servers.json: %w", err)
		}
		source = "embedded"
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("server list empty (both %s and embedded had no entries)", runtimeServersPath)
	}
	serverCache = servers
	shared.Debugf("CyberGhost: loaded %d servers from %s", len(servers), source)
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

// ensurePEMTerminator appends a trailing newline if the input doesn't
// already end with one. OpenSSL's PEM parser rejects a block whose
// END line isn't terminated ("bad end line" error) — and the
// OpenBao web UI silently strips the trailing newline when a user
// pastes a multi-line value into the form. Belt-and-braces fix here.
func ensurePEMTerminator(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
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
	if err = os.WriteFile(certPath, []byte(ensurePEMTerminator(cert)), 0600); err != nil {
		err = fmt.Errorf("write client.crt: %w", err)
		return
	}
	keyPath = filepath.Join(dir, clientKeyName)
	if err = os.WriteFile(keyPath, []byte(ensurePEMTerminator(key)), 0600); err != nil {
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

// isOpenVPNConnected returns true once the tunnel's redirect-gateway
// push has actually taken effect — i.e. a route LOOKUP for an
// arbitrary public address resolves via tun0, not via eth0. The
// looser "any route on tun0 exists" variant we use elsewhere
// returns true too early: openvpn installs the per-pod link-local
// route (e.g. 10.2.4.0/24 dev tun0) BEFORE the redirect-gateway
// default-eclipsing routes are pushed, so the exit-IP contract
// probe in cmd/tundler-tunnel/egress.go would fire while the main-
// ns default route is still via eth0 and flag a leak that doesn't
// actually exist.
//
// `ip route get 8.8.8.8` returns the route the kernel would pick
// for that dst RIGHT NOW; checking for " dev tun0 " in the output
// confirms the tunnel is genuinely the path packets are taking.
//
// The same fix is mirrored in protonvpn.go and surfshark.go's
// OpenVPN branch (the WireGuard branch doesn't have this race —
// wg-quick is synchronous, routes are installed before it returns).
//
// 8.8.8.8 is a stable public-IPv4 destination; we don't actually
// send a packet to it, this is purely a kernel route-table lookup.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev tun0 ")
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
