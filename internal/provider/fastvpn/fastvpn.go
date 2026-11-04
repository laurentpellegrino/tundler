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
//     provider: tun-fastvpn carries the default route, the upstream sees a
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
// untouched except for the credential, interface and lifecycle lines
// and, in warp mode, an appended `socks-proxy` line.
//
// Process: one owned openvpn child per connection, supervised over a
// management socket (internal/shared/ovpn, as ipvanish / veepn /
// protonvpn): the password travels over the socket, a server that
// refuses the credentials is reported as such (Status.AuthFailed)
// instead of timing out like a dead edge, the tunnel comes up on a
// fixed tun-fastvpn and Disconnect stops exactly that process.
package fastvpn

import (
	"context"
	"errors"
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
	"github.com/laurentpellegrino/tundler/internal/shared/ovpn"
	"github.com/laurentpellegrino/tundler/internal/shared/warpproxy"
)

const (
	name             = "fastvpn"
	defaultConfigDir = "/etc/fastvpn/configs"
	defaultRunDir    = "/run/fastvpn"

	transportWarp   = "warp"
	transportDirect = "direct"

	// tunnelInterface is the fixed tun name the tunnel comes up on
	// (15 characters is the kernel limit).
	tunnelInterface = "tun-fastvpn"
	// connectTimeout bounds one attempt: management startup, TLS
	// handshake and the CONNECTED state (the old route poll gave up
	// after 30 s).
	connectTimeout = 30 * time.Second
	// routeTimeout bounds the wait for the pushed redirect-gateway to
	// become the main-namespace default route after CONNECTED.
	routeTimeout = 10 * time.Second
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
	serverCache   []fastvpnServer
	serverCacheMu sync.RWMutex
	activeMu      sync.RWMutex
	current       *active
	loggedIn      bool

	// startTunnel launches the owned openvpn; tests replace it.
	startTunnel = ovpn.Start

	// Filename format: NCVPN-<CC>-<City>[ - Virtual]-<UDP|TCP>.ovpn
	filenameRe = regexp.MustCompile(`^NCVPN-([A-Z]{2})-(.+)-(?:UDP|TCP)\.ovpn$`)

	// Directives dropped from the vendor config before ours are
	// appended: credentials come over the management socket, the
	// interface is pinned, the process lifecycle is the runner's.
	// Everything else (remotes, remote-random, ciphers, tls-cipher,
	// persist-*) is kept as the --daemon version ran it.
	droppedDirectiveRe = regexp.MustCompile(`(?m)^[ \t]*(auth-user-pass|dev|dev-type|management[a-z-]*|daemon|log|log-append|auth-retry|auth-nocache)\b.*\n?`)
	// Inline blocks (<ca>…</ca>) are kept verbatim: the directive
	// filter runs on the lines outside them only.
	inlineBlockRe = regexp.MustCompile(`(?s)<([a-z-]+)>.*?</[a-z-]+>`)
)

// active is the owned tunnel and where it goes.
type active struct {
	tunnel   *ovpn.Tunnel
	server   *fastvpnServer
	location string
}

func init() {
	provider.Registry[name] = FastVPN{}
	accounts.RegisterLegacyShim(name, accounts.LegacyEnvFields(map[string]string{
		accounts.FieldUsername: "FASTVPN_USERNAME",
		accounts.FieldPassword: "FASTVPN_PASSWORD",
	}))
}

func runDir() string {
	if d := os.Getenv("FASTVPN_RUN_DIR"); d != "" {
		return d
	}
	return defaultRunDir
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

// openVPNConfig turns the chosen city's vendor .ovpn into the config
// this provider runs: transport and keys kept, credential, interface
// and lifecycle lines replaced by ours, and in warp mode the TCP edge
// dialed through WARP's SOCKS proxy. socket is the management socket.
func openVPNConfig(vendor []byte, socket string, viaWarp bool) ([]byte, error) {
	if !ovpn.ValidSocket(socket) {
		return nil, errors.New("invalid FastVPN management socket path")
	}
	text := strings.ReplaceAll(string(vendor), "\r\n", "\n")
	var blocks []string
	text = inlineBlockRe.ReplaceAllStringFunc(text, func(b string) string {
		blocks = append(blocks, b)
		return fmt.Sprintf("\x00BLOCK%d\x00", len(blocks)-1)
	})
	text = droppedDirectiveRe.ReplaceAllString(text, "")
	for i, b := range blocks {
		text = strings.Replace(text, fmt.Sprintf("\x00BLOCK%d\x00", i), b, 1)
	}
	text = strings.TrimRight(text, "\n") + "\n"
	ours := "\n# --- tundler ---\ndev " + tunnelInterface + "\ndev-type tun\n" + ovpn.Directives(socket)
	if viaWarp {
		ours += "socks-proxy " + warpproxy.Addr + "\n"
	}
	return []byte(text + ours), nil
}

// ----------------------------------------------------------------------
// OpenVPN process
// ----------------------------------------------------------------------

// isOpenVPNConnected reports whether the tunnel is the path packets
// take RIGHT NOW: a route lookup for a public address resolves via the
// tunnel interface (the pushed redirect-gateway has landed).
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
		shared.Debugf("FastVPN: %v", err)
	}
}

// ----------------------------------------------------------------------
// provider.VPNProvider
// ----------------------------------------------------------------------

func (f FastVPN) ActiveLocation(ctx context.Context) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil {
		return ""
	}
	return current.location
}

func (f FastVPN) Connect(ctx context.Context, location string) provider.Status {
	failed := provider.Status{Connected: false, Provider: name, Location: location}
	user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("FastVPN: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}

	viaWarp := transport() == transportWarp
	if viaWarp {
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
		return failed
	}
	server := pickRandomServer(matches)
	vendor, err := os.ReadFile(filepath.Join(configDir(), server.Filename))
	if err != nil {
		shared.Debugf("FastVPN: read %s: %v", server.Filename, err)
		return failed
	}

	// One tunnel at a time: drop whatever we own before dialing.
	disconnect(ctx)

	tunnel, err := startTunnel(ctx, ovpn.Options{Name: "FastVPN", RunDir: runDir(), CD: configDir(), User: user, Pass: pass, Timeout: connectTimeout},
		func(socket string) ([]byte, error) { return openVPNConfig(vendor, socket, viaWarp) })
	if errors.Is(err, ovpn.ErrAuthFailed) {
		// The credential is shared by every pod; when one edge refuses
		// it the runtime skips this location and connects elsewhere.
		shared.Debugf("FastVPN: %s/%s: %v", server.Country, server.City, err)
		failed.AuthFailed = true
		return failed
	}
	if err != nil {
		shared.Debugf("FastVPN: %s/%s: %v", server.Country, server.City, err)
		return failed
	}
	if !waitForRoute(ctx, tunnel) {
		shared.Debugf("FastVPN: %s/%s: connected but the default route never moved to %s", server.Country, server.City, tunnelInterface)
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
		_ = tunnel.Stop(stopCtx)
		cancel()
		return failed
	}
	activeMu.Lock()
	current = &active{tunnel: tunnel, server: server, location: location}
	activeMu.Unlock()
	return f.Status(ctx)
}

func (f FastVPN) Connected(ctx context.Context) bool {
	activeMu.RLock()
	a := current
	activeMu.RUnlock()
	return a != nil && a.tunnel.Address() != "" && isOpenVPNConnected()
}

// Disconnect stops openvpn only. WARP stays up — it is transport,
// not the rotating identity — and with no tunnel the host falls back
// to its own egress, which the crawler never uses (the proxy answers
// 502 until the next Connect).
func (f FastVPN) Disconnect(ctx context.Context) error {
	disconnect(ctx)
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
