package ipvanish

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
	name             = "ipvanish"
	defaultConfigDir = "/etc/ipvanish/openvpn"
	activeConfigName = "active.ovpn"
	credentialsName  = "auth.txt"
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

var (
	serverCache    []ipvanishServer
	serverCacheMu  sync.RWMutex
	activeServer   *ipvanishServer
	activeLocation string
	activeMu       sync.RWMutex
	loggedIn       bool

	// Filename format: ipvanish-<CC>-<City-with-hyphens>[---Virtual]-<3letter>-<a|b|c>NN(N).ovpn
	filenameRe = regexp.MustCompile(`^ipvanish-([A-Z]{2})-(.+)-([a-z]{3})-([abc]\d+)\.ovpn$`)

	// Matches a bare "auth-user-pass" directive (no file argument), which
	// IPVanish ships in every config. We rewrite it so OpenVPN reads our
	// credentials file instead of prompting interactively.
	authUserPassRe = regexp.MustCompile(`(?m)^auth-user-pass\s*$`)

	// IPVanish configs still carry directives OpenVPN 2.6 either rejects
	// outright (keysize) or warns about as insecure (comp-lzo enables
	// receive-side compression, which underlies the VORACLE attack). Strip
	// both so the daemon starts and compression stays off.
	deprecatedDirectivesRe = regexp.MustCompile(`(?m)^(keysize|comp-lzo)\b.*$`)
)

func init() { provider.Registry[name] = IPVanish{} }

func configDir() string {
	if dir := os.Getenv("IPVANISH_CONFIG_DIR"); dir != "" {
		return dir
	}
	return defaultConfigDir
}

func getCredentials() (string, string, error) {
	user := os.Getenv("IPVANISH_USERNAME")
	pass := os.Getenv("IPVANISH_PASSWORD")
	if user == "" || pass == "" {
		return "", "", fmt.Errorf("IPVANISH_USERNAME and IPVANISH_PASSWORD environment variables must be set")
	}
	return user, pass, nil
}

// parseFilename turns a config filename into an ipvanishServer entry, or
// reports false when the filename doesn't match IPVanish's convention.
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

	country, ok := countryName(cc)
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

func pickRandomServer(servers []ipvanishServer) *ipvanishServer {
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

func writeActiveConfig(server *ipvanishServer, credentialsFile string) (string, error) {
	src := filepath.Join(configDir(), server.Filename)
	raw, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", src, err)
	}
	rewritten := authUserPassRe.ReplaceAllString(string(raw), "auth-user-pass "+credentialsFile)
	rewritten = deprecatedDirectivesRe.ReplaceAllString(rewritten, "")

	dst := filepath.Join(configDir(), activeConfigName)
	if err := os.WriteFile(dst, []byte(rewritten), 0600); err != nil {
		return "", fmt.Errorf("failed to write active config: %w", err)
	}
	return dst, nil
}

// isOpenVPNConnected returns true once openvpn has finished tunnel
// setup — checking the route table (not just link UP) because
// OpenVPN brings the link up before pushing routes, and we want to
// match the post-route point at which traffic can actually flow.
// Uses RunCmdSilent so the connect-poll loop (60 iterations × 500ms)
// doesn't swamp journald with "Cannot find device tun0" / exit-1
// messages while the tunnel is still coming up.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "show", "dev", "tun0")
	return err == nil && strings.TrimSpace(out) != ""
}

// ActiveLocation returns whatever was passed to Connect — i.e. an entry from
// Locations(). Reporting the verbatim pool string lets a config block/allow
// list round-trip. Granular per-server detail is exposed via Status.Region.
func (i IPVanish) ActiveLocation(ctx context.Context) string {
	if activeServer == nil {
		return ""
	}
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (i IPVanish) Connect(ctx context.Context, location string) provider.Status {
	user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("IPVanish: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}

	servers, err := loadServers()
	if err != nil {
		shared.Debugf("IPVanish: failed to load servers: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}

	matches := findServers(servers, location)
	if len(matches) == 0 {
		shared.Debugf("IPVanish: no servers found for location: %s", location)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	server := pickRandomServer(matches)
	credFile, err := writeCredentials(user, pass)
	if err != nil {
		shared.Debugf("IPVanish: failed to write credentials: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	if _, err := writeActiveConfig(server, credFile); err != nil {
		shared.Debugf("IPVanish: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	// --cd so the config's relative `ca ca.ipvanish.com.crt` resolves.
	// --tun-mtu / --mssfix clamp packet size below the k8s pod MTU
	// (typically 1370 on Talos/Cilium); without these, OpenVPN's
	// default 1500-byte MTU produces oversized UDP packets that get
	// dropped on the path, causing the TLS handshake to never
	// complete and the connect to time out.
	if _, err := shared.RunCmd(ctx, "openvpn",
		"--cd", configDir(),
		"--config", activeConfigName,
		"--tun-mtu", "1320",
		"--mssfix", "1280",
		"--daemon"); err != nil {
		shared.Debugf("IPVanish: failed to start openvpn: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	for j := 0; j < 60; j++ {
		time.Sleep(500 * time.Millisecond)
		if isOpenVPNConnected() {
			activeServer = server
			activeMu.Lock()
			activeLocation = location
			activeMu.Unlock()
			return i.Status(ctx)
		}
	}

	shared.Debugf("IPVanish: connection timeout for %s", server.Hostname)
	return provider.Status{Connected: false, Provider: name, Location: location}
}

func (i IPVanish) Connected(ctx context.Context) bool {
	return isOpenVPNConnected()
}

func (i IPVanish) Disconnect(ctx context.Context) error {
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

func (i IPVanish) Login(ctx context.Context) error {
	if _, _, err := getCredentials(); err != nil {
		return err
	}
	if _, err := loadServers(); err != nil {
		return err
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
	if out, err := shared.RunCmdDirect(ctx, "getent", "ahostsv4", host); err == nil {
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
