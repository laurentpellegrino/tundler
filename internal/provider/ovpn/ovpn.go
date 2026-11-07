// Package ovpn drives OVPN.com over OpenVPN directly (no provider daemon).
// One owned openvpn child per connection, supervised over a management
// socket (internal/shared/ovpn, as windscribe / cyberghost / ipvanish):
// the password travels over the socket, a server that refuses the
// credentials is reported as such (Status.AuthFailed) instead of timing
// out like a dead server, the tunnel comes up on a fixed tun-ovpn and
// Disconnect stops exactly that process.
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
	"errors"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
	ovpnrun "github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

const (
	name          = "ovpn"
	serversFile   = "/etc/ovpn/servers.json"
	defaultRunDir = "/run/ovpn"
	// tunnelInterface is the fixed tun name the tunnel comes up on
	// (15 characters is the kernel limit).
	tunnelInterface = "tun-ovpn"
	// connectTimeout bounds one attempt: management startup, TLS
	// handshake and the CONNECTED state (the old route poll gave up
	// after 30 s).
	connectTimeout = 30 * time.Second
	// routeTimeout bounds the wait for the pushed redirect-gateway to
	// become the main-namespace default route after CONNECTED.
	routeTimeout = 10 * time.Second
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
	serverCache   []Server
	serverCacheMu sync.RWMutex
	activeMu      sync.RWMutex
	current       *active
	loggedIn      bool
)

// startTunnel launches the owned openvpn; tests replace it.
var startTunnel = ovpnrun.Start

// active is the owned tunnel and where it goes.
type active struct {
	tunnel   *ovpnrun.Tunnel
	server   Server
	location string
}

func runDir() string {
	if d := os.Getenv("OVPN_RUN_DIR"); d != "" {
		return d
	}
	return defaultRunDir
}

func init() {
	provider.Registry[name] = OVPN{}
	accounts.RegisterLegacyShim(name, accounts.LegacyEnvFields(map[string]string{
		accounts.FieldUsername: "OVPN_USERNAME",
		accounts.FieldPassword: "OVPN_PASSWORD",
	}))
}

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

// buildOpenVPNConfig renders the config from OVPN's directives (taken
// verbatim from a downloaded config) with the embedded CA + tls-auth and
// the chosen server's two UDP remotes (1194/1195, remote-random). The
// transport and data-channel directives are the ones the --daemon version
// ran with; the credential, interface, MTU clamp (formerly command-line
// flags) and lifecycle lines changed with the move to the owned process.
// socket is the management socket the owned openvpn answers on.
func buildOpenVPNConfig(server *Server, socket string) (string, error) {
	if !ovpnrun.ValidSocket(socket) {
		return "", errors.New("invalid OVPN management socket path")
	}
	host := server.hostname()
	// --tun-mtu / --mssfix clamp packet size below the k8s pod MTU so
	// the TLS handshake's UDP packets aren't dropped (same values
	// ipvanish uses). connect-retry-max 1 tries each remote once.
	return fmt.Sprintf(`client
dev %s
dev-type tun
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
key-direction 1
tun-mtu 1320
mssfix 1280
connect-retry-max 1
%s<ca>
%s
</ca>
<tls-auth>
%s
</tls-auth>
`, tunnelInterface, host, host, ovpnrun.Directives(socket),
		strings.TrimSpace(embeddedCACert), strings.TrimSpace(embeddedTLSAuth)), nil
}

// isOpenVPNConnected returns true once the redirect-gateway push has taken
// effect: a route lookup for an arbitrary public address resolves via the
// tunnel interface, not eth0. The looser "any route on the tun exists"
// check trips too early (before the default-eclipsing routes),
// false-positiving the exit-IP contract probe. Runs in the MAIN namespace,
// where the in-process CONNECT proxy dials with a plain net.DialTimeout.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev "+tunnelInterface+" ")
}

func waitForRoute(ctx context.Context, tunnel *ovpnrun.Tunnel) bool {
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
		shared.Debugf("OVPN: %v", err)
	}
}

func (o OVPN) ActiveLocation(ctx context.Context) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil {
		return ""
	}
	return current.location
}

func (o OVPN) Connect(ctx context.Context, location string) provider.Status {
	failed := provider.Status{Connected: false, Provider: name, Location: location}
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
		return failed
	}
	server := pickRandomServer(matches)

	// One tunnel at a time: drop whatever we own before dialing.
	disconnect(ctx)

	tunnel, err := startTunnel(ctx, ovpnrun.Options{Name: "OVPN", RunDir: runDir(), User: user, Pass: pass, Timeout: connectTimeout},
		func(socket string) ([]byte, error) {
			cfg, err := buildOpenVPNConfig(server, socket)
			return []byte(cfg), err
		})
	if errors.Is(err, ovpnrun.ErrAuthFailed) {
		// The credential is shared by every pod; when one server
		// refuses it the runtime skips this location and connects
		// elsewhere.
		shared.Debugf("OVPN: %s: %v", server.hostname(), err)
		failed.AuthFailed = true
		return failed
	}
	if err != nil {
		shared.Debugf("OVPN: %s: %v", server.hostname(), err)
		return failed
	}
	if !waitForRoute(ctx, tunnel) {
		shared.Debugf("OVPN: %s: connected but the default route never moved to %s", server.hostname(), tunnelInterface)
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
		_ = tunnel.Stop(stopCtx)
		cancel()
		return failed
	}
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: *server, location: location}
	activeMu.Unlock()
	return o.Status(ctx)
}

func (o OVPN) Connected(ctx context.Context) bool {
	activeMu.RLock()
	a := current
	activeMu.RUnlock()
	return a != nil && a.tunnel.Address() != "" && isOpenVPNConnected()
}

func (o OVPN) Disconnect(ctx context.Context) error {
	disconnect(ctx)
	return nil
}

// Daemonless marks the tunnel as an owned openvpn child (see
// provider.Daemonless).
func (OVPN) Daemonless() {}

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

func (o OVPN) LoggedIn(ctx context.Context) bool {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return loggedIn
}

func (o OVPN) Login(ctx context.Context) error {
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

func (o OVPN) Logout(ctx context.Context) error {
	activeMu.Lock()
	loggedIn = false
	activeMu.Unlock()
	return nil
}

func (o OVPN) Status(ctx context.Context) provider.Status {
	if !o.Connected(ctx) {
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

func (o OVPN) Version(ctx context.Context) (string, error) {
	servers, err := loadServers()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("openvpn (%d datacenters)", len(servers)), nil
}
