// Package fastvpn is an OpenVPN-direct provider for Namecheap's
// FastVPN service. White-labels WLVPN's backbone (*.vpn.wlvpn.com).
//
// Auth model: 2-factor — username + password, generated separately
// from the Namecheap dashboard login at FastVPN account panel →
// "Network access information". Cred is shared across pods
// (FastVPN allows unlimited concurrent OpenVPN sessions), so no
// per-pod credential isolation is needed unlike cyberghost.
//
// Server discovery: each pod ships a directory of UDP-only .ovpn
// files (one per city) baked at image build time from the
// fastvpn-configs GitHub release (mirror of the public
// https://vpn.ncapi.io/groupedServerList.zip, refreshed daily —
// see .github/workflows/update-fastvpn-configs.yml). Each .ovpn
// contains MULTIPLE `remote ...` entries with `remote-random`, so
// openvpn itself load-balances across the city's edge IPs — we
// don't need to do anything clever runtime-side.
//
// Filename convention (parseable for Locations() metadata):
//   NCVPN-<CC>-<City>[ - Virtual]-UDP.ovpn
//
// CA cert is INLINED in every .ovpn (`<ca>...</ca>` block), so no
// embedded ca.crt either. We pass the .ovpn through openvpn
// untouched except for overriding `auth-user-pass` to point at
// our credentials file (the upstream config has a bare
// `auth-user-pass` directive that would otherwise prompt on TTY).
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

	// Filename format: NCVPN-<CC>-<City>[ - Virtual]-UDP.ovpn
	// City may contain spaces and hyphens, "Virtual" suffix is
	// optional. Capture: 1=CC, 2=city-tail (with optional Virtual).
	filenameRe = regexp.MustCompile(`^NCVPN-([A-Z]{2})-(.+)-UDP\.ovpn$`)

	// Bare `auth-user-pass` directive (no file argument) — present
	// in every upstream .ovpn. We rewrite it so openvpn reads our
	// credentials file instead of prompting on TTY.
	authUserPassRe = regexp.MustCompile(`(?m)^auth-user-pass\s*$`)
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

// parseFilename extracts (CC, city, virtual) from an .ovpn filename
// like `NCVPN-DE-Frankfurt-UDP.ovpn` or
// `NCVPN-AM-Yerevan - Virtual-UDP.ovpn`. Returns false if the name
// doesn't match the expected pattern.
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

// writeActiveConfig copies the chosen city's .ovpn into a known
// location with the bare `auth-user-pass` directive rewritten to
// reference our credentials file. Everything else (the CA inlined
// in <ca>...</ca>, the multiple `remote ...` lines, modern cipher
// defaults) is passed through untouched.
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

// isOpenVPNConnected returns true once the tunnel's redirect-gateway
// push has actually taken effect — i.e. a route lookup for an
// arbitrary public address resolves via tun0, not via eth0. Same
// race-fix-style check as cyberghost / protonvpn / surfshark's
// OpenVPN branch — gates against the per-pod link-local route on
// tun0 fooling the contract probe into firing before the default-
// eclipsing routes are installed.
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

	// --tun-mtu / --mssfix clamp below the k8s pod MTU. RunCmd
	// (post-bb88d29 default — main netns) so openvpn + tun0 land
	// in the same namespace as the in-process CONNECT proxy.
	if _, err := shared.RunCmd(ctx, "openvpn",
		"--cd", configDir(),
		"--config", activeConfigName,
		"--tun-mtu", "1320",
		"--mssfix", "1280",
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
