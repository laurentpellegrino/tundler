// Package fastvpn is an OpenVPN-direct provider for Namecheap's
// FastVPN service, tunneled INSIDE a Cloudflare WARP transport.
//
// Why nested (WARP → OpenVPN → FastVPN):
// FastVPN white-labels WLVPN's backbone (*.vpn.wlvpn.com). WLVPN's
// edge blocks datacenter IP ranges at L3 (confirmed: TCP/443 and
// UDP/1194 to every WLVPN edge time out from our Hetzner nodes,
// while a generic Cloudflare host is reachable). To present an
// acceptable source IP we route openvpn's OUTER packets through
// Cloudflare WARP — WLVPN then sees a Cloudflare exit IP and
// accepts the connection. Crawler traffic still exits via
// FastVPN's tun0 (the innermost tunnel), so the upstream sees a
// FastVPN IP, not Cloudflare's.
//
// The routing dance (see setupNestedRouting): WARP captures all
// unmarked traffic via a policy-routing rule at priority 32764
// (table 65743 → CloudflareWARP). Left alone, that shadows
// openvpn's main-table split-default and every byte would exit via
// WARP. We add three assertions around the openvpn launch:
//   1. pin each WLVPN remote /32 → dev CloudflareWARP (outer
//      tunnel rides WARP),
//   2. pin Cloudflare WARP's edge ranges → via eth0 gateway (so
//      WARP's own WireGuard transport doesn't loop into FastVPN's
//      tun0 — the circular-routing deadlock),
//   3. add `ip rule from all lookup main pref 32763` (one priority
//      above WARP's catch-all) so main — carrying openvpn's
//      0.0.0.0/1 via tun0 — governs general traffic.
// All three are idempotent and survive warp-svc's route daemon
// (we add a higher-priority rule rather than deleting WARP's).
//
// Auth model: 2-factor — username + password, generated separately
// from the Namecheap dashboard login at FastVPN account panel →
// "Network access information". FastVPN allows unlimited concurrent
// OpenVPN sessions, so one shared cred works across N pods.
//
// Server discovery: each pod ships a directory of UDP-only .ovpn
// files (one per city) baked at image build time from the
// fastvpn-configs GitHub release (mirror of the public
// https://vpn.ncapi.io/groupedServerList.zip, refreshed daily).
// Each .ovpn carries multiple `remote ...` entries + `remote-random`;
// the CA is inlined (`<ca>...</ca>`). We pass the .ovpn through
// untouched except for rewriting the bare `auth-user-pass` directive.
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

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	name             = "fastvpn"
	defaultConfigDir = "/etc/fastvpn/configs"
	activeConfigName = "active.ovpn"
	credentialsName  = "auth.txt"

	warpCli = "warp-cli"
	// warpEdgeRange is Cloudflare's WARP anycast block. Modern WARP
	// uses MASQUE (HTTP/3 over QUIC) — its endpoints are scattered
	// across 162.159.x (observed: 162.159.198.2:8095 for the MASQUE
	// tunnel, 162.159.36.1 / 162.159.46.1 for DoH) — NOT the legacy
	// 162.159.192/193 WireGuard pair. We pin the whole /16 via the
	// original eth0 gateway so WARP's OWN transport (control + data)
	// always takes the direct path and never gets routed into
	// FastVPN's tun0 — that circular dependency (FastVPN-needs-WARP,
	// WARP-would-need-FastVPN) was what deadlocked WARP's MASQUE
	// reconnect and tripped its always-on kill switch, EPERM-
	// rejecting openvpn's packets. 162.159.0.0/16 is Cloudflare
	// infra, never a crawl target, so pinning it costs no exit
	// diversity.
	warpEdgeRange = "162.159.0.0/16"
	// mainBeatWarpPref is one priority ABOVE warp-svc's catch-all
	// rule (32764) so the main table — with openvpn's pushed
	// 0.0.0.0/1 via tun0 — is consulted first for general traffic.
	mainBeatWarpPref = "32763"
	// remoteViaWarpPref is BELOW mainBeatWarpPref so the WLVPN remote
	// rule wins over the main-beats-warp diversion: openvpn's outer
	// packets to the WLVPN edge take WARP's NATIVE table (the same
	// path standalone-WARP app traffic uses), which is the only way
	// they pass WARP's kill-switch nftables (a hand-rolled
	// /32-via-CloudflareWARP route in the main table gets
	// EPERM-rejected — WARP only accepts traffic that flows through
	// its own routing table).
	remoteViaWarpPref = "100"
	warpDev           = "CloudflareWARP"
	// FastVPN/WLVPN push these internal DNS resolvers in their
	// PUSH_REPLY; they're reachable only through tun0. We point
	// resolv.conf at them once the tunnel is up, replacing WARP's
	// hijacked + flaky local stub (127.0.2.x). Resolving via FastVPN
	// also keeps DNS geo-consistent with the exit.
	fastvpnDNS = "nameserver 198.18.0.1\nnameserver 198.18.0.2\n"
	resolvConf = "/etc/resolv.conf"
)

var warpFlags = []string{"--accept-tos"}

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

	// Filename format: NCVPN-<CC>-<City>[ - Virtual]-UDP.ovpn
	filenameRe = regexp.MustCompile(`^NCVPN-([A-Z]{2})-(.+)-UDP\.ovpn$`)

	// Bare `auth-user-pass` directive (no file argument) — present
	// in every upstream .ovpn. We rewrite it so openvpn reads our
	// credentials file instead of prompting on TTY.
	authUserPassRe = regexp.MustCompile(`(?m)^auth-user-pass\s*$`)

	// `remote <host> <port>` lines — we resolve each host and pin
	// the resulting IPs through WARP.
	remoteRe = regexp.MustCompile(`(?m)^remote\s+(\S+)`)
)

func init() { provider.Registry[name] = FastVPN{} }

func configDir() string {
	if dir := os.Getenv("FASTVPN_CONFIG_DIR"); dir != "" {
		return dir
	}
	return defaultConfigDir
}

func getCredentials() (string, string, error) {
	user := os.Getenv("FASTVPN_USERNAME")
	pass := os.Getenv("FASTVPN_PASSWORD")
	if user == "" || pass == "" {
		return "", "", fmt.Errorf(
			"FASTVPN_USERNAME and FASTVPN_PASSWORD must be set " +
				"(from FastVPN dashboard → Account Panel → Network access information)")
	}
	return user, pass, nil
}

// ----------------------------------------------------------------------
// WARP transport
// ----------------------------------------------------------------------

func warpRun(ctx context.Context, args ...string) (string, error) {
	return shared.RunCmd(ctx, warpCli, append(append([]string(nil), warpFlags...), args...)...)
}

// warpOn probes Cloudflare's trace endpoint — the authoritative
// "tunnel is actually routing" signal (warp-cli status flips to
// Connected a moment before traffic flows).
func warpOn(ctx context.Context) bool {
	out, err := shared.RunCmd(ctx, "curl", "-s", "--max-time", "3",
		"https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return false
	}
	for _, ln := range strings.Split(out, "\n") {
		if strings.TrimSpace(ln) == "warp=on" {
			return true
		}
	}
	return false
}

// warpUp ensures the WARP transport tunnel is connected. Idempotent:
// re-registers only if no live registration, then connects and
// polls until warp=on. Unlike the standalone warp provider, we do
// NOT delete the registration on rotation — WARP is pure transport
// here, not the rotating exit identity (FastVPN provides that).
func warpUp(ctx context.Context) error {
	if warpOn(ctx) {
		return nil
	}
	reg, _ := warpRun(ctx, "registration", "show")
	low := strings.ToLower(reg)
	if !strings.Contains(low, "device id") && !strings.Contains(low, "account") {
		if _, err := warpRun(ctx, "registration", "new"); err != nil {
			return fmt.Errorf("warp registration new: %w", err)
		}
	}
	_, _ = warpRun(ctx, "mode", "warp")
	if _, err := warpRun(ctx, "connect"); err != nil {
		return fmt.Errorf("warp connect: %w", err)
	}
	for i := 0; i < 60; i++ {
		if warpOn(ctx) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("warp did not reach warp=on within 30s")
}

// origDefaultGateway returns the eth0 next-hop from the main table's
// default route. With WARP up this stays "via <gw> dev eth0" (WARP
// routes via its own policy table 65743, leaving main's default
// pointing at eth0).
func origDefaultGateway(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, "ip", "route", "show", "default", "dev", "eth0")
	if err != nil || strings.TrimSpace(out) == "" {
		// Fall back to the unscoped default.
		out, err = shared.RunCmd(ctx, "ip", "route", "show", "default")
		if err != nil {
			return "", err
		}
	}
	// Parse "default via 10.0.x.2 dev eth0 ..."
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no `via` gateway in default route: %q", out)
}

// resolveRemotes extracts every `remote <host>` from the active
// config and resolves each to its IPv4 address(es).
func resolveRemotes(ctx context.Context, configPath string) ([]string, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var ips []string
	seen := map[string]bool{}
	for _, m := range remoteRe.FindAllStringSubmatch(string(raw), -1) {
		host := m[1]
		out, err := shared.RunCmd(ctx, "getent", "ahostsv4", host)
		if err != nil {
			shared.Debugf("FastVPN: getent %s failed: %v", host, err)
			continue
		}
		for _, ln := range strings.Split(out, "\n") {
			if ip := shared.FirstIPv4(ln); ip != "" && !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolved no remote IPs from %s", configPath)
	}
	return ips, nil
}

// warpTableNum reads the routing-table number WARP captures traffic
// into, from its policy-routing rule (`not from all fwmark 0x...
// lookup <N>`). Observed as 65743, but WARP picks it dynamically so
// we never hard-code it.
func warpTableNum(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, "ip", "rule", "show")
	if err != nil {
		return "", err
	}
	// Match the WARP rule line and grab the table after "lookup".
	for _, ln := range strings.Split(out, "\n") {
		if !strings.Contains(ln, "fwmark") || !strings.Contains(ln, "lookup") {
			continue
		}
		fields := strings.Fields(ln)
		for i, f := range fields {
			if f == "lookup" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
	}
	return "", fmt.Errorf("no WARP fwmark/lookup rule found in: %q", out)
}

// flushRemoteViaWarpRules deletes any leftover remote-via-WARP rules
// at remoteViaWarpPref so a reconnect to a different city doesn't
// accumulate stale rules. `ip rule del` removes one match per call;
// loop until none remain (bounded).
func flushRemoteViaWarpRules(ctx context.Context) {
	for i := 0; i < 64; i++ {
		if _, err := shared.RunCmd(ctx, "ip", "rule", "del", "pref", remoteViaWarpPref); err != nil {
			return
		}
	}
}

// setupNestedRouting installs the routing assertions that make the
// WARP→OpenVPN→FastVPN nesting deliver a FastVPN exit. See the
// package doc for the full rationale. Idempotent.
func setupNestedRouting(ctx context.Context, remoteIPs []string) error {
	gw, err := origDefaultGateway(ctx)
	if err != nil {
		return fmt.Errorf("find original gateway: %w", err)
	}
	warpTable, err := warpTableNum(ctx)
	if err != nil {
		return fmt.Errorf("find WARP table: %w", err)
	}
	// (a) Pin WARP's anycast block via eth0 so WARP transport never
	// loops into tun0. /16 is more specific than openvpn's eventual
	// 0.0.0.0/1, so order vs openvpn doesn't matter.
	if _, err := shared.RunCmd(ctx, "ip", "route", "replace", warpEdgeRange, "via", gw, "dev", "eth0"); err != nil {
		return fmt.Errorf("pin warp edge %s: %w", warpEdgeRange, err)
	}
	// (b) Route each WLVPN remote through WARP's NATIVE table at a
	// priority below mainBeatWarpPref so it wins over the
	// main-beats-warp diversion for the remote dest. Using WARP's
	// own table (not a hand-rolled CloudflareWARP route) is what
	// makes these packets pass WARP's kill-switch nft rules.
	flushRemoteViaWarpRules(ctx)
	for _, ip := range remoteIPs {
		if _, err := shared.RunCmd(ctx, "ip", "rule", "add", "to", ip+"/32",
			"lookup", warpTable, "pref", remoteViaWarpPref); err != nil {
			return fmt.Errorf("route remote %s via WARP table %s: %w", ip, warpTable, err)
		}
	}
	// (c) Make main beat WARP's catch-all (pref 32764) so openvpn's
	// pushed 0.0.0.0/1 via tun0 governs general traffic. Del-then-add
	// keeps it idempotent across reconnects.
	_, _ = shared.RunCmd(ctx, "ip", "rule", "del", "pref", mainBeatWarpPref)
	if _, err := shared.RunCmd(ctx, "ip", "rule", "add", "from", "all", "lookup", "main", "pref", mainBeatWarpPref); err != nil {
		return fmt.Errorf("add main-beats-warp rule: %w", err)
	}
	shared.Debugf("FastVPN: nested routing set (gw=%s, warp-table=%s, %d remote IPs via WARP)",
		gw, warpTable, len(remoteIPs))
	return nil
}

// teardownNestedRouting removes the rules we added so that between
// rotations (openvpn down) traffic falls back to WARP's catch-all
// rather than leaking out the node IP. The /16 edge pin is left in
// place — harmless and re-asserted on the next Connect.
func teardownNestedRouting(ctx context.Context) {
	_, _ = shared.RunCmd(ctx, "ip", "rule", "del", "pref", mainBeatWarpPref)
	flushRemoteViaWarpRules(ctx)
}

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

	var servers []fastvpnServer
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fname := e.Name()
		if !strings.HasPrefix(fname, "NCVPN-") || !strings.HasSuffix(fname, "-UDP.ovpn") {
			continue
		}
		cc, city, virtual, ok := parseFilename(fname)
		if !ok {
			shared.Debugf("FastVPN: skipping unparseable %s", fname)
			continue
		}
		country, found := countryName(cc)
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
		return nil, fmt.Errorf("no FastVPN OpenVPN configs found in %s", dir)
	}

	serverCache = servers
	shared.Debugf("FastVPN: loaded %d OpenVPN configs", len(servers))
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
	dir := configDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, credentialsName)
	if err := os.WriteFile(path, []byte(user+"\n"+pass+"\n"), 0600); err != nil {
		return "", err
	}
	return path, nil
}

func writeActiveConfig(server *fastvpnServer, credentialsFile string) (string, error) {
	src := filepath.Join(configDir(), server.Filename)
	raw, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", src, err)
	}
	rewritten := authUserPassRe.ReplaceAllString(string(raw), "auth-user-pass "+credentialsFile)
	dst := filepath.Join(configDir(), activeConfigName)
	if err := os.WriteFile(dst, []byte(rewritten), 0600); err != nil {
		return "", fmt.Errorf("write active config: %w", err)
	}
	return dst, nil
}

// isOpenVPNConnected returns true once openvpn's pushed
// redirect-gateway has taken effect — a route lookup for an
// arbitrary public address resolves via tun0. Because the
// main-beats-warp rule (pref 32763) makes the main table win, this
// flips to tun0 exactly when openvpn installs its 0.0.0.0/1 split
// default (not the per-pod link-local route). Same default-route
// gating as the other openvpn-direct providers.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev tun0 ")
}

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

	// WARP transport must be up before openvpn — the outer tunnel
	// rides it to dodge WLVPN's datacenter-IP block.
	if err := warpUp(ctx); err != nil {
		shared.Debugf("FastVPN: WARP transport not ready: %v", err)
		return provider.Status{Connected: false, Provider: name}
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
	activePath, err := writeActiveConfig(server, credFile)
	if err != nil {
		shared.Debugf("FastVPN: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	// Resolve the chosen city's WLVPN edge IPs and pin them through
	// WARP before openvpn opens its socket.
	remoteIPs, err := resolveRemotes(ctx, activePath)
	if err != nil {
		shared.Debugf("FastVPN: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	if err := setupNestedRouting(ctx, remoteIPs); err != nil {
		shared.Debugf("FastVPN: nested routing failed: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	// --tun-mtu 1200 / --mssfix 1160: WARP's WireGuard MTU is 1280;
	// openvpn rides inside it, so the inner payload ceiling is well
	// below the usual 1370 pod path. These leave headroom for both
	// the WARP and OpenVPN headers.
	if _, err := shared.RunCmd(ctx, "openvpn",
		"--cd", configDir(),
		"--config", activeConfigName,
		"--tun-mtu", "1200",
		"--mssfix", "1160",
		"--daemon"); err != nil {
		shared.Debugf("FastVPN: failed to start openvpn: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	for j := 0; j < 60; j++ {
		time.Sleep(500 * time.Millisecond)
		if isOpenVPNConnected() {
			// Repoint DNS away from WARP's hijacked stub to
			// FastVPN's pushed resolvers (via tun0). Must happen
			// before Status()/the contract probe, which both
			// resolve hostnames.
			if err := os.WriteFile(resolvConf, []byte(fastvpnDNS), 0644); err != nil {
				shared.Debugf("FastVPN: could not repoint resolv.conf to FastVPN DNS: %v", err)
			}
			activeServer = server
			activeMu.Lock()
			activeLocation = location
			activeMu.Unlock()
			return f.Status(ctx)
		}
	}

	shared.Debugf("FastVPN: connection timeout for %s/%s", server.Country, server.City)
	return provider.Status{Connected: false, Provider: name, Location: location}
}

func (f FastVPN) Connected(ctx context.Context) bool {
	return isOpenVPNConnected()
}

func (f FastVPN) Disconnect(ctx context.Context) error {
	_, _ = shared.RunCmd(ctx, "pkill", "-SIGTERM", "openvpn")
	for j := 0; j < 20; j++ {
		if !isOpenVPNConnected() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Drop the main-beats-warp rule so the rotation window (openvpn
	// down) exits via WARP rather than leaking the node IP. WARP
	// itself stays up — it's transport, not the rotating identity.
	teardownNestedRouting(ctx)
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
	// Bring WARP transport up at login so the first Connect() has
	// it ready. Non-fatal if it isn't up yet — Connect() re-checks
	// and retries warpUp.
	if err := warpUp(ctx); err != nil {
		shared.Debugf("FastVPN: WARP not up at login (will retry on Connect): %v", err)
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
