// Package ipvanish is the IPVanish provider: OpenVPN-direct from the
// vendor's official .ovpn set (baked into the image from the
// `ipvanish-configs` GitHub release), one owned openvpn child per
// connection supervised over a private management socket (openvpn.go).
//
// What makes IPVanish different from the other OpenVPN-direct providers
// is its anti-abuse rule: too many logins in a short window suspends the
// whole account for about 24 hours, every further login extends the
// suspension, and a suspended account answers every connect with
// AUTH_FAILED. The 2026-05 outage was exactly that spiral — the old
// provider could not tell AUTH_FAILED from a dead server, reported a
// "connection timeout", and the runtime's retry kept logging in. So this
// provider classifies AUTH_FAILED (Status.AuthFailed) and the runtime
// holds every connect for a long, growing backoff when it sees it; the
// fleet keeps ipvanish on a 24 h rotation window for the same reason.
//
// Every connect is a login, so Connect tries at most a couple of servers
// of the requested location, never the whole pool, and never retries
// after AUTH_FAILED.
//
// Outer transport (IPVANISH_TRANSPORT):
//
//   - warp (default): IPVanish drops datacenter source IPs at L3 (from
//     Hetzner its servers answer neither ping nor TCP 443; from a
//     residential line both work — verified 2026-10-27). The OpenVPN
//     connection rides Cloudflare WARP in proxy mode (see
//     internal/shared/warpproxy): TCP/443 to the same server through the
//     local SOCKS5 proxy, which presents a Cloudflare source IP.
//   - direct: the vendor config as is, UDP, no WARP. For hosts whose
//     own source IP IPVanish accepts (residential lines).
package ipvanish

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	"github.com/laurentpellegrino/tundler/internal/geo"
	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
	"github.com/laurentpellegrino/tundler/internal/shared/warpproxy"
)

const (
	name             = "ipvanish"
	defaultConfigDir = "/etc/ipvanish/openvpn"
	envTransport     = "IPVANISH_TRANSPORT"
	transportWarp    = "warp"
	transportDirect  = "direct"
	defaultRunDir    = "/run/ipvanish"
	// connectTimeout bounds one openvpn attempt: management startup,
	// TLS handshake and the CONNECTED state.
	connectTimeout = 35 * time.Second
	// routeTimeout bounds the wait for the pushed redirect-gateway to
	// become the main-namespace default route after CONNECTED.
	routeTimeout = 10 * time.Second
	// serversPerConnect caps how many servers of a location one Connect
	// tries. Each try is a login against the abuse-rate rule.
	serversPerConnect = 2
)

type IPVanish struct{}

type ipvanishServer struct {
	Country  string
	CC       string
	City     string
	Hostname string
	Virtual  bool
	Filename string
}

// active is the current connection: the owned openvpn child plus what
// it was asked to connect to.
type active struct {
	tunnel   *openVPNTunnel
	server   *ipvanishServer
	location string
}

var (
	// Filename format: ipvanish-<CC>-<City-with-hyphens>[---Virtual]-<3letter>-<a|b|c>NN(N).ovpn
	filenameRe = regexp.MustCompile(`^ipvanish-([A-Z]{2})-(.+)-([a-z]{3})-([abc]\d+)\.ovpn$`)

	serverCache   []ipvanishServer
	serverCacheMu sync.RWMutex

	activeMu sync.RWMutex
	current  *active

	loggedIn bool
)

func init() {
	provider.Registry[name] = IPVanish{}
	accounts.RegisterLegacyShim(name, accounts.LegacyEnvFields(map[string]string{
		accounts.FieldUsername: "IPVANISH_USERNAME",
		accounts.FieldPassword: "IPVANISH_PASSWORD",
	}))
}

func configDir() string {
	if dir := os.Getenv("IPVANISH_CONFIG_DIR"); dir != "" {
		return dir
	}
	return defaultConfigDir
}

// runDir holds the per-connection config and management socket
// (tmpfs in the image; Unix socket paths are limited to 107 bytes).
func runDir() string {
	if dir := os.Getenv("IPVANISH_RUN_DIR"); dir != "" {
		return dir
	}
	return defaultRunDir
}

// transport returns the configured outer transport: warp (default) or
// direct. Unknown values fall back to warp with a log line.
func transport() string {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(envTransport)))
	switch raw {
	case "", transportWarp:
		return transportWarp
	case transportDirect:
		return transportDirect
	default:
		shared.Debugf("IPVanish: unknown %s=%q, using %s", envTransport, raw, transportWarp)
		return transportWarp
	}
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

// parseFilename turns a config filename into an ipvanishServer entry, or
// reports false when the filename doesn't match IPVanish's convention:
// ipvanish-<CC>-<City-with-hyphens>[---Virtual]-<3letter>-<a|b|c>NN(N).ovpn
func parseFilename(filename string) (ipvanishServer, bool) {
	m := filenameRe.FindStringSubmatch(filename)
	if m == nil {
		return ipvanishServer{}, false
	}
	cc, city, hostPrefix, hostSuffix := m[1], m[2], m[3], m[4]

	virtual := false
	if strings.HasSuffix(city, "---Virtual") {
		virtual = true
		city = strings.TrimSuffix(city, "---Virtual")
	}
	city = strings.ReplaceAll(city, "-", " ")

	// IPVanish filenames use "UK" (not "GB"); geo's code alias
	// resolves it. Unknown codes degrade to the bare CC.
	country, ok := geo.CountryName(cc)
	if !ok {
		country = cc
	}

	return ipvanishServer{
		Country:  country,
		CC:       cc,
		City:     city,
		Hostname: fmt.Sprintf("%s-%s.ipvanish.com", hostPrefix, hostSuffix),
		Virtual:  virtual,
		Filename: filename,
	}, true
}

func loadServers() ([]ipvanishServer, error) {
	serverCacheMu.RLock()
	if len(serverCache) > 0 {
		cached := append([]ipvanishServer(nil), serverCache...)
		serverCacheMu.RUnlock()
		return cached, nil
	}
	serverCacheMu.RUnlock()

	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()
	if len(serverCache) > 0 {
		return append([]ipvanishServer(nil), serverCache...), nil
	}

	dir := configDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", dir, err)
	}

	var servers []ipvanishServer
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fname := e.Name()
		if !strings.HasPrefix(fname, "ipvanish-") || !strings.HasSuffix(fname, ".ovpn") {
			continue
		}
		srv, ok := parseFilename(fname)
		if !ok {
			shared.Debugf("IPVanish: skipping unparseable %s", fname)
			continue
		}
		servers = append(servers, srv)
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("no IPVanish OpenVPN configs found in %s", dir)
	}

	serverCache = servers
	shared.Debugf("IPVanish: loaded %d OpenVPN configs", len(servers))
	return append([]ipvanishServer(nil), servers...), nil
}

func findServers(servers []ipvanishServer, location string) []ipvanishServer {
	if location == "" {
		return servers
	}
	want := strings.ToLower(location)
	var matches []ipvanishServer
	for _, s := range servers {
		if strings.ToLower(s.Country) == want ||
			strings.ToLower(s.CC) == want ||
			strings.ToLower(s.City) == want {
			matches = append(matches, s)
		}
	}
	return matches
}

// isOpenVPNConnected reports whether the tunnel is the path packets
// take RIGHT NOW: a route lookup for a public address resolves via the
// tunnel interface. The looser "the interface exists" check is true too
// early (openvpn adds the link-local route before the redirect-gateway
// routes), which would trip the exit-IP contract probe on a leak that
// does not exist. Main namespace: openvpn runs there, see openvpn.go.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev "+tunnelInterface+" ")
}

// waitForRoute waits for the pushed default route to land.
func waitForRoute(ctx context.Context, tunnel *openVPNTunnel) bool {
	deadline := time.Now().Add(routeTimeout)
	for time.Now().Before(deadline) && ctx.Err() == nil && tunnel.address() != "" {
		if isOpenVPNConnected() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// ActiveLocation returns whatever was passed to Connect — i.e. an entry from
// Locations(). Reporting the verbatim pool string lets a config block/allow
// list round-trip. Granular per-server detail is exposed via Status.Region.
func (i IPVanish) ActiveLocation(ctx context.Context) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil {
		return ""
	}
	return current.location
}

func (i IPVanish) Connect(ctx context.Context, location string) provider.Status {
	failed := provider.Status{Connected: false, Provider: name, Location: location}
	user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("IPVanish: %v", err)
		return failed
	}
	servers, err := loadServers()
	if err != nil {
		shared.Debugf("IPVanish: failed to load servers: %v", err)
		return failed
	}
	matches := findServers(servers, location)
	if len(matches) == 0 {
		shared.Debugf("IPVanish: no servers found for location: %s", location)
		return failed
	}

	// One tunnel at a time: drop whatever we own before dialing.
	disconnect(ctx)

	if transport() == transportWarp {
		// The SOCKS proxy must forward before openvpn dials through
		// it, and WARP's own packets must never be routed into the
		// tunnel openvpn is about to bring up.
		if err := warpproxy.Up(ctx); err != nil {
			shared.Debugf("IPVanish: WARP transport not ready: %v", err)
			return failed
		}
		if err := warpproxy.PinEdge(ctx); err != nil {
			shared.Debugf("IPVanish: %v", err)
			return failed
		}
	}

	rand.Shuffle(len(matches), func(a, b int) { matches[a], matches[b] = matches[b], matches[a] })
	for idx := range matches {
		if idx >= serversPerConnect || ctx.Err() != nil {
			break
		}
		server := &matches[idx]
		tunnel, err := startTunnel(ctx, server, user, pass)
		if errors.Is(err, errAuthFailed) {
			// Account-wide: another server would be one more login
			// against the rate rule. Report it so the runtime holds.
			shared.Debugf("IPVanish: %s: %v", server.Hostname, err)
			failed.AuthFailed = true
			return failed
		}
		if err != nil {
			shared.Debugf("IPVanish: %s: %v", server.Hostname, err)
			continue
		}
		if !waitForRoute(ctx, tunnel) {
			shared.Debugf("IPVanish: %s: connected but the default route never moved to %s", server.Hostname, tunnelInterface)
			stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
			_ = tunnel.stop(stopCtx)
			cancel()
			continue
		}
		activeMu.Lock()
		current = &active{tunnel: tunnel, server: server, location: location}
		activeMu.Unlock()
		return i.Status(ctx)
	}
	return failed
}

func (i IPVanish) Connected(ctx context.Context) bool {
	activeMu.RLock()
	a := current
	activeMu.RUnlock()
	return a != nil && a.tunnel.address() != "" && isOpenVPNConnected()
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
	if err := a.tunnel.stop(stopCtx); err != nil {
		shared.Debugf("IPVanish: %v", err)
	}
}

func (i IPVanish) Disconnect(ctx context.Context) error {
	disconnect(ctx)
	return nil
}

func (i IPVanish) Locations(ctx context.Context) []string {
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

func (i IPVanish) LoggedIn(ctx context.Context) bool { return loggedIn }

// Login only checks that credentials and configs are present: IPVanish
// has no session, every connect authenticates on its own.
func (i IPVanish) Login(ctx context.Context) error {
	if _, _, err := getCredentials(); err != nil {
		return err
	}
	if _, err := loadServers(); err != nil {
		return err
	}
	if transport() == transportWarp {
		// Bring the WARP proxy up at login so the first Connect has
		// it ready. Non-fatal: Connect re-checks and retries.
		if err := warpproxy.Up(ctx); err != nil {
			shared.Debugf("IPVanish: WARP not up at login (will retry on Connect): %v", err)
		}
	}
	loggedIn = true
	return nil
}

func (i IPVanish) Logout(ctx context.Context) error {
	loggedIn = false
	return nil
}

func (i IPVanish) Status(ctx context.Context) provider.Status {
	if !i.Connected(ctx) {
		return provider.Status{Connected: false, Provider: name}
	}
	status := provider.Status{
		Connected: true,
		Location:  i.ActiveLocation(ctx),
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
	if current.server.City != "" {
		return current.server.Country + " - " + current.server.City
	}
	return current.server.Country
}

func (i IPVanish) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, "openvpn", "--version")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0]), nil
}
