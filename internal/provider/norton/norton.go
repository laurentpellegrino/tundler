// Package norton drives Norton VPN (the SurfEasy / Gen Digital backend, the
// same stack as Avast SecureLine) over OpenVPN directly, with no vendor daemon.
// One owned openvpn child per connection, supervised over a management socket
// (internal/shared/ovpn, as ovpn / windscribe / ipvanish): the password travels
// over the socket, a server that refuses the credentials is reported as such
// (Status.AuthFailed) instead of timing out, the tunnel comes up on a fixed
// tun-norton and Disconnect stops exactly that process.
//
// Auth is a per-device OpenVPN username/password minted by the backend when the
// subscription is activated on a device; the username carries the account's
// tenant id. Credentials come one of two ways:
//
//   - stored: NORTON_USERNAME / NORTON_PASSWORD (a device pair harvested once);
//   - self-provisioned: NORTON_PRODUCT_KEY alone, from which the provider
//     activates a device and mints the pair headlessly (see onboard.go). The
//     result is cached in the run dir so a restart reuses the seat.
//
// The CA chain comes with the minted credential (or the embedded fallback); the
// exit servers are the embedded snapshot in servers.json (IP, country and city
// per entry), and the exit IP is the chosen server's IP. The cipher is
// AES-256-GCM, taken from the client's resolved profile.
package norton

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
	ovpnrun "github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

const (
	name          = "norton"
	defaultRunDir = "/run/norton"
	// tunnelInterface is the fixed tun name the tunnel comes up on
	// (15 characters is the kernel limit).
	tunnelInterface = "tun-norton"
	// openvpnPort is the TCP port the backend's OpenVPN servers answer on.
	openvpnPort = 443
	// connectTimeout bounds one attempt: management startup, TLS handshake
	// and the CONNECTED state.
	connectTimeout = 30 * time.Second
	// routeTimeout bounds the wait for the pushed redirect-gateway to become
	// the main-namespace default route after CONNECTED.
	routeTimeout = 10 * time.Second
)

//go:embed ca.crt
var embeddedCACert string

//go:embed servers.json
var embeddedServers []byte

type Norton struct{}

// Server is one OpenVPN exit from the backend's discovery response. The OpenVPN
// remote is the IP directly (the servers are addressed by IP, not hostname).
type Server struct {
	IP          string `json:"ip"`
	Country     string `json:"country"` // ISO code, e.g. "FR"
	City        string `json:"city"`
	LocationKey string `json:"location_key"`
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
	if d := os.Getenv("NORTON_RUN_DIR"); d != "" {
		return d
	}
	return defaultRunDir
}

// fieldProductKey is the account field holding the subscription's product key.
// When it is the only credential supplied, the provider self-provisions a device
// OpenVPN username/password from it (see onboard.go), so a pod can run on the key
// alone with no per-device credential harvested up front.
const fieldProductKey = "product_key"

var (
	provisionMu sync.Mutex
	provisioned *deviceCredential
)

func init() {
	provider.Registry[name] = Norton{}
	accounts.RegisterLegacyShim(name, accounts.LegacyEnvFields(map[string]string{
		accounts.FieldUsername: "NORTON_USERNAME",
		accounts.FieldPassword: "NORTON_PASSWORD",
		fieldProductKey:        "NORTON_PRODUCT_KEY",
	}))
}

// getCredentials resolves the OpenVPN username/password and (optionally) the CA.
// An explicit username/password wins (a pre-minted device credential); otherwise
// the provider self-provisions from the product key and caches the result.
func getCredentials(ctx context.Context) (user, pass, ca string, err error) {
	acct, err := accounts.Current(name)
	if err != nil {
		return "", "", "", err
	}
	u, okU := acct.Line(accounts.FieldUsername)
	p, okP := acct.Line(accounts.FieldPassword)
	if okU && okP {
		return u, p, "", nil
	}
	key, okK := acct.Line(fieldProductKey)
	if !okK {
		// No explicit creds and no key: surface the field the operator should set.
		_, rerr := acct.Require(fieldProductKey)
		return "", "", "", rerr
	}
	cred, err := provisionFromProductKey(ctx, key)
	if err != nil {
		return "", "", "", err
	}
	return cred.Username, cred.Password, cred.CA, nil
}

// credentialCachePath is where a self-provisioned credential is stored so a
// restart reuses it rather than re-activating the key.
func credentialCachePath() string {
	return filepath.Join(runDir(), "credential.json")
}

// provisionFromProductKey returns a device credential minted from the product
// key, reusing an in-memory or on-disk cache before performing a live activation.
func provisionFromProductKey(ctx context.Context, key string) (deviceCredential, error) {
	provisionMu.Lock()
	defer provisionMu.Unlock()
	if provisioned != nil && provisioned.valid() {
		return *provisioned, nil
	}
	if c, ok := loadCachedCredential(); ok {
		provisioned = &c
		return c, nil
	}
	c, err := onboardWithProductKey(ctx, key, machineIdentityFor(defaultMachineSeed()))
	if err != nil {
		return deviceCredential{}, err
	}
	provisioned = &c
	saveCachedCredential(c)
	return c, nil
}

func loadCachedCredential() (deviceCredential, bool) {
	raw, err := os.ReadFile(credentialCachePath())
	if err != nil {
		return deviceCredential{}, false
	}
	var c deviceCredential
	if err := json.Unmarshal(raw, &c); err != nil || !c.valid() {
		return deviceCredential{}, false
	}
	return c, true
}

func saveCachedCredential(c deviceCredential) {
	raw, err := json.Marshal(c)
	if err != nil {
		return
	}
	if err := os.MkdirAll(runDir(), 0o700); err != nil {
		shared.Debugf("norton: cache credential: %v", err)
		return
	}
	if err := os.WriteFile(credentialCachePath(), raw, 0o600); err != nil {
		shared.Debugf("norton: cache credential: %v", err)
	}
}

const defaultServersFile = "/etc/norton/servers.json"

// serversFilePath is the refreshable exit snapshot — the `norton-servers`
// release asset baked into the image by update-norton-servers, mirroring
// proton/cyberghost. NORTON_SERVERS_FILE overrides it; the embedded snapshot is
// the fallback when the file is absent.
func serversFilePath() string {
	if p := strings.TrimSpace(os.Getenv("NORTON_SERVERS_FILE")); p != "" {
		return p
	}
	return defaultServersFile
}

// loadServers parses the exit snapshot (the refreshable file if present, else
// the embedded fallback), cached for the process lifetime.
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

	data := embeddedServers
	if fileData, err := os.ReadFile(serversFilePath()); err == nil && len(fileData) > 0 {
		data = fileData
	}
	var raw []Server
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse servers: %w", err)
	}
	var servers []Server
	for _, s := range raw {
		if s.IP == "" {
			continue
		}
		servers = append(servers, s)
	}
	if len(servers) == 0 {
		return nil, errors.New("no servers in embedded snapshot")
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].IP < servers[j].IP })
	serverCache = servers
	shared.Debugf("norton: loaded %d exit servers", len(servers))
	return append([]Server(nil), servers...), nil
}

// findServers filters by country code/name or city, case-insensitive.
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

// buildOpenVPNConfig renders the OpenVPN config for the chosen server. The
// tunnel directives are taken verbatim from the backend's own OpenVPN template
// (assets/vpn-nlok.conf): remote-cert-tls server, the single AES-256-GCM cipher
// (from the client's resolved profile), route 0.0.0.0 0.0.0.0 and its ping /
// reconnect timing. Management is tundler's owned-process form (the credential
// travels over the socket via ovpnrun.Directives, so no auth-user-pass file is
// written), the dev is a fixed name so Disconnect and the route probe can find
// it, and tun-mtu / mssfix clamp packet size below the pod MTU. socket is that
// management socket.
func buildOpenVPNConfig(server *Server, socket, ca string) (string, error) {
	if !ovpnrun.ValidSocket(socket) {
		return "", errors.New("invalid norton management socket path")
	}
	ca = strings.TrimSpace(ca)
	if ca == "" {
		ca = strings.TrimSpace(embeddedCACert)
	}
	return fmt.Sprintf(`client
tls-client
dev %s
dev-type tun
verb 1
mute-replay-warnings
remote %s %d tcp
nobind
reneg-sec 0
route 0.0.0.0 0.0.0.0
remote-cert-tls server
cipher AES-256-GCM
data-ciphers AES-256-GCM
resolv-retry 1
connect-retry 3 10
connect-retry-max 1
ping 10
ping-restart 15
hand-window 10
allow-recursive-routing
tun-mtu 1320
mssfix 1280
%s<ca>
%s
</ca>
`, tunnelInterface, server.IP, openvpnPort, ovpnrun.Directives(socket), ca), nil
}

// isOpenVPNConnected returns true once the redirect-gateway push has taken
// effect: a route lookup for an arbitrary public address resolves via the
// tunnel interface, not eth0.
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
		shared.Debugf("norton: %v", err)
	}
}

func (n Norton) ActiveLocation(ctx context.Context) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil {
		return ""
	}
	return current.location
}

func (n Norton) Connect(ctx context.Context, location string) provider.Status {
	failed := provider.Status{Connected: false, Provider: name, Location: location}
	user, pass, ca, err := getCredentials(ctx)
	if err != nil {
		shared.Debugf("norton: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	servers, err := loadServers()
	if err != nil {
		shared.Debugf("norton: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	matches := findServers(servers, location)
	if len(matches) == 0 {
		shared.Debugf("norton: no servers for location: %s", location)
		return failed
	}
	server := pickRandomServer(matches)

	// One tunnel at a time: drop whatever we own before dialing.
	disconnect(ctx)

	tunnel, err := startTunnel(ctx, ovpnrun.Options{Name: "norton", RunDir: runDir(), User: user, Pass: pass, Timeout: connectTimeout},
		func(socket string) ([]byte, error) {
			cfg, err := buildOpenVPNConfig(server, socket, ca)
			return []byte(cfg), err
		})
	if errors.Is(err, ovpnrun.ErrAuthFailed) {
		shared.Debugf("norton: %s: %v", server.IP, err)
		failed.AuthFailed = true
		return failed
	}
	if err != nil {
		shared.Debugf("norton: %s: %v", server.IP, err)
		return failed
	}
	if !waitForRoute(ctx, tunnel) {
		shared.Debugf("norton: %s: connected but the default route never moved to %s", server.IP, tunnelInterface)
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
		_ = tunnel.Stop(stopCtx)
		cancel()
		return failed
	}
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: *server, location: location}
	activeMu.Unlock()
	return n.Status(ctx)
}

func (n Norton) Connected(ctx context.Context) bool {
	activeMu.RLock()
	a := current
	activeMu.RUnlock()
	return a != nil && a.tunnel.Address() != "" && isOpenVPNConnected()
}

func (n Norton) Disconnect(ctx context.Context) error {
	disconnect(ctx)
	return nil
}

// Daemonless marks the tunnel as an owned openvpn child (see
// provider.Daemonless).
func (Norton) Daemonless() {}

func (n Norton) Locations(ctx context.Context) []string {
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

func (n Norton) LoggedIn(ctx context.Context) bool {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return loggedIn
}

func (n Norton) Login(ctx context.Context) error {
	if _, _, _, err := getCredentials(ctx); err != nil {
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

func (n Norton) Logout(ctx context.Context) error {
	activeMu.Lock()
	loggedIn = false
	activeMu.Unlock()
	return nil
}

func (n Norton) Status(ctx context.Context) provider.Status {
	if !n.Connected(ctx) {
		return provider.Status{Connected: false, Provider: name}
	}
	status := provider.Status{
		Connected: true,
		Location:  n.ActiveLocation(ctx),
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

func (n Norton) Version(ctx context.Context) (string, error) {
	servers, err := loadServers()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("openvpn (%d servers)", len(servers)), nil
}
