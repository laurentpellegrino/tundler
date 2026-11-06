// Package cyberghost is an OpenVPN-direct provider for CyberGhost VPN.
// One owned openvpn child per connection, supervised over a management
// socket (internal/shared/ovpn, as windscribe / ipvanish / protonvpn):
// the password travels over the socket, a server that refuses the
// device credentials is reported as such (Status.AuthFailed) instead of
// timing out like a dead server, the tunnel comes up on a fixed
// tun-cyberghost and Disconnect stops exactly that process.
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
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
	"github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

const (
	name          = "cyberghost"
	defaultRunDir = "/run/cyberghost"
	// tunnelInterface is the fixed tun name the tunnel comes up on
	// (15 characters is the kernel limit).
	tunnelInterface = "tun-cyberghost"
	// connectTimeout bounds one attempt: management startup, TLS
	// handshake, the 5 s route-delay and the CONNECTED state (the old
	// route poll gave up 30 s after the daemon started).
	connectTimeout = 35 * time.Second
	// routeTimeout bounds the wait for the pushed redirect-gateway to
	// become the main-namespace default route after CONNECTED.
	routeTimeout = 10 * time.Second
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
	serverCache   []cyberghostServer
	serverCacheMu sync.RWMutex
	activeMu      sync.RWMutex
	current       *active
	loggedIn      bool
)

// startTunnel launches the owned openvpn; tests replace it.
var startTunnel = ovpn.Start

// active is the owned tunnel and where it goes.
type active struct {
	tunnel   *ovpn.Tunnel
	server   cyberghostServer
	location string
}

func init() {
	provider.Registry[name] = CyberGhost{}
	accounts.RegisterLegacyShim(name, accounts.LegacyShim{
		Accounts: legacyCredsDirShim,
		// The legacy source is a FILE (the pre-accounts Secret
		// projection), not an env var.
		Hint: func(field string) string {
			return fmt.Sprintf("%s/POD_%d_%s", credsDir,
				accounts.PodOrdinal(), strings.ToUpper(field))
		},
	})
}

func runDir() string {
	if dir := os.Getenv("CYBERGHOST_RUN_DIR"); dir != "" {
		return dir
	}
	return defaultRunDir
}

// credsDir is where the pre-accounts StatefulSet projected the
// vpn-credentials-cyberghost Secret as a directory (one flat file per
// POD_<n>_* key). Reading from files (not env) sidestepped the
// entrypoint's printenv|grep filter that truncates multi-line PEMs to
// their first line — the very bug the accounts directory now solves for
// every provider. This path survives only as the legacy shim below.
const credsDir = "/etc/cyberghost/creds"

// legacyCredsDirShim synthesizes Slots=1 accounts from the flat
// POD_<n>_{CERTIFICATE,KEY,USERNAME,PASSWORD} files under credsDir,
// scanning ordinals from 0 until the first gap — the file-based twin of
// accounts.LegacyPerPodEnv.
func legacyCredsDirShim() []accounts.Account {
	var accts []accounts.Account
	for n := 0; ; n++ {
		prefix := fmt.Sprintf("POD_%d_", n)
		acct := accounts.Account{ID: fmt.Sprintf("pod-%d", n), Slots: 1, Fields: map[string]string{}}
		complete := true
		for field, suffix := range map[string]string{
			accounts.FieldCertificate: "CERTIFICATE",
			accounts.FieldKey:         "KEY",
			accounts.FieldUsername:    "USERNAME",
			accounts.FieldPassword:    "PASSWORD",
		} {
			b, err := os.ReadFile(filepath.Join(credsDir, prefix+suffix))
			if err != nil || len(b) == 0 {
				complete = false
				break
			}
			acct.Fields[field] = string(b)
		}
		if !complete {
			return accts
		}
		accts = append(accts, acct)
	}
}

// getCredentials returns this pod's (cert, key, username, password)
// quadruple from its account. username and password are trimmed of
// surrounding whitespace; cert and key are passed through untouched
// (PEM is whitespace-sensitive).
func getCredentials() (cert, key, user, pass string, err error) {
	acct, err := accounts.Current(name)
	if err != nil {
		return "", "", "", "", err
	}
	if cert, err = acct.RequireRaw(accounts.FieldCertificate); err != nil {
		return "", "", "", "", err
	}
	if key, err = acct.RequireRaw(accounts.FieldKey); err != nil {
		return "", "", "", "", err
	}
	if user, err = acct.Require(accounts.FieldUsername); err != nil {
		return "", "", "", "", err
	}
	if pass, err = acct.Require(accounts.FieldPassword); err != nil {
		return "", "", "", "", err
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

// pemBlock trims a PEM value for an inline config block and rejects
// one that could close the block early.
func pemBlock(field, v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || strings.Contains(v, "<") {
		return "", fmt.Errorf("CyberGhost %s is not a usable PEM block", field)
	}
	return v, nil
}

// buildOpenVPNConfig renders the config for one server. Shape mirrors
// the bundle CyberGhost's dashboard generates (extracted from a real
// Configure Device download: same data-ciphers, ping, etc.). The
// transport and data-channel directives are the ones the --daemon
// version ran with; the credential, interface, MTU clamp (formerly
// command-line flags) and lifecycle lines changed with the move to the
// owned process. The per-device cert and key are inline: the config
// lives in the private connection directory, removed when the process
// ends. socket is the management socket the owned openvpn answers on.
func buildOpenVPNConfig(server *cyberghostServer, cert, key, socket string) (string, error) {
	if !ovpn.ValidSocket(socket) {
		return "", errors.New("invalid CyberGhost management socket path")
	}
	cert, err := pemBlock("certificate", cert)
	if err != nil {
		return "", err
	}
	key, err = pemBlock("key", key)
	if err != nil {
		return "", err
	}
	// --tun-mtu / --mssfix clamp below the k8s pod MTU (1370 on
	// Talos/Cilium); default 1500-byte payloads get PMTU-dropped on
	// the encapsulated path.
	return fmt.Sprintf(`client
remote %s 443
dev %s
dev-type tun
proto udp
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
tun-mtu 1320
mssfix 1280
connect-retry-max 1
%s<ca>
%s
</ca>
<cert>
%s
</cert>
<key>
%s
</key>
`, server.Hostname, tunnelInterface, ovpn.Directives(socket),
		strings.TrimSpace(string(embeddedCACert)), cert, key), nil
}

// isOpenVPNConnected returns true once the tunnel's redirect-gateway
// push has actually taken effect, i.e. a route LOOKUP for an arbitrary
// public address resolves via the tunnel interface, not via eth0. The
// looser "any route on the tun exists" check returns true too early:
// openvpn installs the per-pod link-local route BEFORE the
// redirect-gateway default-eclipsing routes, so the exit-IP contract
// probe in cmd/tundler-tunnel/egress.go would fire while the main-ns
// default route is still via eth0 and flag a leak that doesn't exist.
//
// 8.8.8.8 is a stable public-IPv4 destination; we don't actually send
// a packet to it, this is purely a kernel route-table lookup.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev "+tunnelInterface+" ")
}

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
		shared.Debugf("CyberGhost: %v", err)
	}
}

func (c CyberGhost) ActiveLocation(ctx context.Context) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil {
		return ""
	}
	return current.location
}

func (c CyberGhost) Connect(ctx context.Context, location string) provider.Status {
	failed := provider.Status{Connected: false, Provider: name, Location: location}
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
		return failed
	}
	server := pickRandomServer(matches)

	// One tunnel at a time: drop whatever we own before dialing.
	disconnect(ctx)

	tunnel, err := startTunnel(ctx, ovpn.Options{Name: "CyberGhost", RunDir: runDir(), User: user, Pass: pass, Timeout: connectTimeout},
		func(socket string) ([]byte, error) {
			cfg, err := buildOpenVPNConfig(server, cert, key, socket)
			return []byte(cfg), err
		})
	if errors.Is(err, ovpn.ErrAuthFailed) {
		// This pod's device profile was refused by one server; the
		// runtime skips this location and connects elsewhere.
		shared.Debugf("CyberGhost: %s: %v", server.Hostname, err)
		failed.AuthFailed = true
		return failed
	}
	if err != nil {
		shared.Debugf("CyberGhost: %s: %v", server.Hostname, err)
		return failed
	}
	if !waitForRoute(ctx, tunnel) {
		shared.Debugf("CyberGhost: %s: connected but the default route never moved to %s", server.Hostname, tunnelInterface)
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
		_ = tunnel.Stop(stopCtx)
		cancel()
		return failed
	}
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: *server, location: location}
	activeMu.Unlock()
	return c.Status(ctx)
}

func (c CyberGhost) Connected(ctx context.Context) bool {
	activeMu.RLock()
	a := current
	activeMu.RUnlock()
	return a != nil && a.tunnel.Address() != "" && isOpenVPNConnected()
}

func (c CyberGhost) Disconnect(ctx context.Context) error {
	disconnect(ctx)
	return nil
}

// Daemonless marks the tunnel as an owned openvpn child (see
// provider.Daemonless).
func (CyberGhost) Daemonless() {}

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

func (c CyberGhost) LoggedIn(ctx context.Context) bool {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return loggedIn
}

func (c CyberGhost) Login(ctx context.Context) error {
	if _, _, _, _, err := getCredentials(); err != nil {
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

func (c CyberGhost) Logout(ctx context.Context) error {
	activeMu.Lock()
	loggedIn = false
	activeMu.Unlock()
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
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil {
		return ""
	}
	if current.server.City != "" {
		return current.server.Country + " - " + current.server.City
	}
	return current.server.Country
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
