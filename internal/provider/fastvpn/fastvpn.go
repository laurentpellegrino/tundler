// Package fastvpn is an OpenVPN-direct provider for Namecheap's
// FastVPN service (WLVPN backbone, *.vpn.wlvpn.com).
//
// Transport (FASTVPN_TRANSPORT):
//
//   - warp (default): WLVPN's edge blocks datacenter source IPs at
//     L3 (TCP/443 and UDP/1194 to every edge time out from Hetzner
//     nodes, while a generic Cloudflare host is reachable). Cloudflare
//     WARP presents a Cloudflare source IP that WLVPN accepts, so
//     openvpn's OUTER connection rides WARP. WARP runs in *proxy mode*
//     (`warp-cli mode proxy`): a local SOCKS5 proxy on 127.0.0.1:40000
//     and nothing else — no CloudflareWARP device, no policy routing,
//     no nftables kill switch, no resolv.conf hijack, no IPv6 path.
//     openvpn connects to the city's TCP/443 edge through that proxy
//     (`socks-proxy`; OpenVPN's SOCKS support is TCP-only) and the
//     inner tunnel then behaves like every other OpenVPN-direct
//     provider: tun0 carries the default route, the upstream sees a
//     FastVPN exit, rotation only restarts openvpn.
//
//     The one routing assertion left: Cloudflare's 162.159.0.0/16
//     (WARP's MASQUE endpoints and DoH resolvers) is pinned via the
//     original eth0 gateway so openvpn's redirect-gateway never
//     swallows WARP's own transport packets (that circular dependency
//     stalls WARP's reconnect).
//
//     History: tunnel mode (WARP as the system default route with
//     openvpn nested inside) also delivers a FastVPN exit, but only
//     after punching accept rules for tun* into WARP's policy-drop
//     input and output chains, re-routing its DoH upstreams through
//     its device and disabling IPv6 on it — and warp-svc rebuilds that
//     ruleset on every interface change, i.e. on every rotation.
//     Proxy mode has none of that.
//
//   - direct: plain openvpn over UDP/1194, no WARP at all. For hosts
//     whose source IP WLVPN accepts (residential, mobile).
//
// Auth model: 2-factor — username + password, generated separately
// from the Namecheap dashboard login at FastVPN account panel →
// "Network access information". FastVPN allows unlimited concurrent
// OpenVPN sessions, so one shared cred works across N pods.
//
// Server discovery: each pod ships a directory of .ovpn files (one
// per city and protocol) baked at image build time from the
// fastvpn-configs GitHub release (mirror of the public
// https://vpn.ncapi.io/groupedServerList.zip, refreshed daily).
// Each .ovpn carries multiple `remote ...` entries + `remote-random`;
// the CA is inlined (`<ca>...</ca>`). We pass the .ovpn through
// untouched except for rewriting the bare `auth-user-pass` directive
// and, in warp mode, appending the `socks-proxy` line.
package fastvpn

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
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
	name             = "fastvpn"
	defaultConfigDir = "/etc/fastvpn/configs"
	activeConfigName = "active.ovpn"
	credentialsName  = "auth.txt"

	transportWarp   = "warp"
	transportDirect = "direct"
)

type FastVPN struct{}

type fastvpnServer struct {
	Country  string
	CC       string
	City     string
	Virtual  bool
	Filename string
}

var (
	serverCache    []fastvpnServer
	serverCacheMu  sync.RWMutex
	activeServer   *fastvpnServer
	activeLocation string
	activeMu       sync.RWMutex
	loggedIn       bool

	// Filename format: NCVPN-<CC>-<City>[ - Virtual]-<UDP|TCP>.ovpn
	filenameRe = regexp.MustCompile(`^NCVPN-([A-Z]{2})-(.+)-(?:UDP|TCP)\.ovpn$`)

	// Bare `auth-user-pass` directive (no file argument) — present
	// in every upstream .ovpn. We rewrite it so openvpn reads our
	// credentials file instead of prompting on TTY.
	authUserPassRe = regexp.MustCompile(`(?m)^auth-user-pass\s*$`)

	// openvpn names its interface tunN with the first free N; after
	// a leftover process or a slow teardown the live tunnel may be
	// tun1, so the connected check must not pin tun0.
	tunRouteRe = regexp.MustCompile(` dev tun\d+ `)
)

func init() {
	provider.Registry[name] = FastVPN{}
	accounts.RegisterLegacyShim(name, accounts.LegacyEnvFields(map[string]string{
		accounts.FieldUsername: "FASTVPN_USERNAME",
		accounts.FieldPassword: "FASTVPN_PASSWORD",
	}))
}

func configDir() string {
	if dir := os.Getenv("FASTVPN_CONFIG_DIR"); dir != "" {
		return dir
	}
	return defaultConfigDir
}

// transport returns the configured outer transport: warp (default)
// or direct. Unknown values fall back to warp with a log line.
func transport() string {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("FASTVPN_TRANSPORT")))
	switch raw {
	case "", transportWarp:
		return transportWarp
	case transportDirect:
		return transportDirect
	default:
		shared.Debugf("FastVPN: unknown FASTVPN_TRANSPORT=%q, using %s", raw, transportWarp)
		return transportWarp
	}
}

// configProto is the .ovpn flavour the transport needs: TCP through
// the WARP SOCKS proxy, UDP when dialing WLVPN directly.
func configProto() string {
	if transport() == transportWarp {
		return "TCP"
	}
	return "UDP"
}

// getCredentials resolves the OpenVPN credential pair — generated
// separately from the Namecheap dashboard login at FastVPN account
// panel → "Network access information".
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

// ----------------------------------------------------------------------
// Server catalog
// ----------------------------------------------------------------------

func loadServers() ([]fastvpnServer, error) {
	serverCacheMu.RLock()
	if len(serverCache) > 0 {
		cached := append([]fastvpnServer(nil), serverCache...)
		serverCacheMu.RUnlock()
		return cached, nil
	}
	serverCacheMu.RUnlock()

	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()
	if len(serverCache) > 0 {
		return append([]fastvpnServer(nil), serverCache...), nil
	}

	dir := configDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", dir, err)
	}

	suffix := "-" + configProto() + ".ovpn"
	var servers []fastvpnServer
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fname := e.Name()
		if !strings.HasPrefix(fname, "NCVPN-") || !strings.HasSuffix(fname, suffix) {
			continue
		}
		cc, city, virtual, ok := parseFilename(fname)
		if !ok {
			shared.Debugf("FastVPN: skipping unparseable %s", fname)
			continue
		}
		// FastVPN filenames use "UK" (not "GB"); geo's code alias
		// resolves it. Unknown codes degrade to the bare CC — safe,
		// just less pretty Locations() output.
		country, found := geo.CountryName(cc)
		if !found {
			country = cc
		}
		servers = append(servers, fastvpnServer{
			Country:  country,
			CC:       cc,
			City:     city,
			Virtual:  virtual,
			Filename: fname,
		})
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("no FastVPN %s OpenVPN configs found in %s", configProto(), dir)
	}

	serverCache = servers
	shared.Debugf("FastVPN: loaded %d %s OpenVPN configs", len(servers), configProto())
	return append([]fastvpnServer(nil), servers...), nil
}

func parseFilename(fname string) (cc, city string, virtual bool, ok bool) {
	m := filenameRe.FindStringSubmatch(fname)
	if m == nil {
		return "", "", false, false
	}
	cc = m[1]
	city = m[2]
	if strings.HasSuffix(city, " - Virtual") {
		virtual = true
		city = strings.TrimSuffix(city, " - Virtual")
	}
	return cc, city, virtual, true
}

func findServers(servers []fastvpnServer, location string) []fastvpnServer {
	if location == "" {
		return servers
	}
	want := strings.ToLower(location)
	var matches []fastvpnServer
	for _, s := range servers {
		if strings.ToLower(s.Country) == want ||
			strings.ToLower(s.CC) == want ||
			strings.ToLower(s.City) == want {
			matches = append(matches, s)
		}
	}
	return matches
}

func pickRandomServer(servers []fastvpnServer) *fastvpnServer {
	if len(servers) == 0 {
		return nil
	}
	s := servers[rand.Intn(len(servers))]
	return &s
}

func writeCredentials(user, pass string) (string, error) {
	return shared.WriteUserPassFile(configDir(), credentialsName, user, pass)
}

// writeActiveConfig copies the chosen city's .ovpn to active.ovpn,
// pointing `auth-user-pass` at our credentials file and, in warp
// mode, dialing the TCP edge through WARP's SOCKS proxy.
func writeActiveConfig(server *fastvpnServer, credentialsFile string) (string, error) {
	src := filepath.Join(configDir(), server.Filename)
	raw, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", src, err)
	}
	rewritten := authUserPassRe.ReplaceAllString(string(raw), "auth-user-pass "+credentialsFile)
	if transport() == transportWarp {
		rewritten = strings.TrimRight(rewritten, "\n") + "\nsocks-proxy " + warpproxy.Addr + "\n"
	}
	dst := filepath.Join(configDir(), activeConfigName)
	if err := os.WriteFile(dst, []byte(rewritten), 0600); err != nil {
		return "", fmt.Errorf("write active config: %w", err)
	}
	return dst, nil
}

// ----------------------------------------------------------------------
// OpenVPN process
// ----------------------------------------------------------------------

// isOpenVPNConnected returns true once openvpn's pushed
// redirect-gateway has taken effect — a route lookup for an
// arbitrary public address resolves via a tun interface. Same
// default-route gating as the other openvpn-direct providers.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return tunRouteRe.MatchString(out)
}

func openVPNRunning(ctx context.Context) bool {
	_, err := shared.RunCmdSilent(ctx, "pgrep", "-x", "openvpn")
	return err == nil
}

// stopOpenVPN terminates every openvpn process and waits for the
// tunnel route to go away. Also used when a Connect attempt times
// out: a half-connected openvpn left behind keeps its tunN, the next
// attempt comes up on tunN+1, and the stale route keeps winning.
func stopOpenVPN(ctx context.Context) {
	if !openVPNRunning(ctx) {
		return
	}
	_, _ = shared.RunCmdSilent(ctx, "pkill", "-SIGTERM", "openvpn")
	for j := 0; j < 30; j++ {
		if !openVPNRunning(ctx) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, _ = shared.RunCmdSilent(ctx, "pkill", "-SIGKILL", "openvpn")
	for j := 0; j < 10 && openVPNRunning(ctx); j++ {
		time.Sleep(100 * time.Millisecond)
	}
}

// ----------------------------------------------------------------------
// provider.VPNProvider
// ----------------------------------------------------------------------

func (f FastVPN) ActiveLocation(ctx context.Context) string {
	if activeServer == nil {
		return ""
	}
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (f FastVPN) Connect(ctx context.Context, location string) provider.Status {
	user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("FastVPN: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}

	if transport() == transportWarp {
		// The SOCKS proxy must forward before openvpn dials through
		// it, and WARP's own packets must never be routed into the
		// tunnel openvpn is about to bring up.
		if err := warpproxy.Up(ctx); err != nil {
			shared.Debugf("FastVPN: WARP transport not ready: %v", err)
			return provider.Status{Connected: false, Provider: name}
		}
		if err := warpproxy.PinEdge(ctx); err != nil {
			shared.Debugf("FastVPN: %v", err)
			return provider.Status{Connected: false, Provider: name}
		}
	}

	servers, err := loadServers()
	if err != nil {
		shared.Debugf("FastVPN: failed to load servers: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}

	matches := findServers(servers, location)
	if len(matches) == 0 {
		shared.Debugf("FastVPN: no servers found for location: %s", location)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	server := pickRandomServer(matches)
	credFile, err := writeCredentials(user, pass)
	if err != nil {
		shared.Debugf("FastVPN: failed to write credentials: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	if _, err := writeActiveConfig(server, credFile); err != nil {
		shared.Debugf("FastVPN: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	// Never stack a second openvpn on a leftover one.
	stopOpenVPN(ctx)

	if _, err := shared.RunCmd(ctx, "openvpn",
		"--cd", configDir(),
		"--config", activeConfigName,
		"--daemon"); err != nil {
		shared.Debugf("FastVPN: failed to start openvpn: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	for j := 0; j < 60; j++ {
		time.Sleep(500 * time.Millisecond)
		if isOpenVPNConnected() {
			activeServer = server
			activeMu.Lock()
			activeLocation = location
			activeMu.Unlock()
			return f.Status(ctx)
		}
	}

	shared.Debugf("FastVPN: connection timeout for %s/%s", server.Country, server.City)
	stopOpenVPN(ctx)
	return provider.Status{Connected: false, Provider: name, Location: location}
}

func (f FastVPN) Connected(ctx context.Context) bool {
	return isOpenVPNConnected()
}

// Disconnect stops openvpn only. WARP stays up — it is transport,
// not the rotating identity — and with no tunnel the host falls back
// to its own egress, which the crawler never uses (the proxy answers
// 502 until the next Connect).
func (f FastVPN) Disconnect(ctx context.Context) error {
	stopOpenVPN(ctx)
	activeServer = nil
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
	return nil
}

func (f FastVPN) Locations(ctx context.Context) []string {
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

func (f FastVPN) LoggedIn(ctx context.Context) bool { return loggedIn }

func (f FastVPN) Login(ctx context.Context) error {
	if _, _, err := getCredentials(); err != nil {
		return err
	}
	if _, err := loadServers(); err != nil {
		return err
	}
	if transport() == transportWarp {
		// Bring the WARP proxy up at login so the first Connect() has
		// it ready. Non-fatal if it isn't up yet — Connect() re-checks
		// and retries warpproxy.Up.
		if err := warpproxy.Up(ctx); err != nil {
			shared.Debugf("FastVPN: WARP not up at login (will retry on Connect): %v", err)
		}
	}
	loggedIn = true
	return nil
}

func (f FastVPN) Logout(ctx context.Context) error {
	loggedIn = false
	return nil
}

func (f FastVPN) Status(ctx context.Context) provider.Status {
	if !f.Connected(ctx) {
		return provider.Status{Connected: false, Provider: name}
	}
	status := provider.Status{
		Connected: true,
		Location:  f.ActiveLocation(ctx),
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

func (f FastVPN) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, "openvpn", "--version")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0]), nil
}
