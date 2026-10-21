// Package hidemyass is an OpenVPN-direct provider for HMA (HideMyAss!)
// VPN.
//
// Why OpenVPN-direct (not an official client): HMA discontinued its
// Linux client in February 2023 and never shipped a headless CLI, so
// the only Linux path is OpenVPN against HMA's per-location .ovpn
// profiles. Same model as ipvanish / cyberghost / purevpn.
//
// Config source: HMA's public config mirror
// (vpn.hidemyass.com/vpn-config/) no longer resolves, so the profiles
// are NOT fetched from HMA at build time. They ship as a `configs.zip`
// asset on the `hidemyass-configs` GitHub release of this repo,
// uploaded by the account holder from the HMA dashboard / support
// (docker/providers/hidemyass/install.sh bakes it into the image).
// The loader accepts both layouts HMA has used:
//
//	Country[.Region].City[_LOCnSm][-VirtualXX].UDP.ovpn  (flat, proto suffix)
//	UDP/Country[.Region].City.ovpn, TCP/…                (proto directory)
//
// Auth model: one OpenVPN username + password (the HMA account login)
// shared by every pod, plus the client certificate/key HMA inlines in
// every profile. HMA caps concurrent sessions per account (5 on the
// classic plan, 10 on newer ones), so max_tunnels must stay under that.
//
// Location vocabulary: Locations() returns canonical country names
// ("United States", "United Kingdom") resolved through internal/geo
// from HMA's CamelCase country tokens ("USA", "UnitedKingdom"), so
// the region-spread walk and EXCLUDED_LOCATIONS see the same names
// every other country-catalog provider exposes.
package hidemyass

import (
	"context"
	"fmt"
	"io/fs"
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
)

const (
	name             = "hidemyass"
	defaultConfigDir = "/etc/hidemyass/openvpn"
	activeConfigName = "active.ovpn"
	credentialsName  = "auth.txt"
)

type HideMyAss struct{}

type hmaServer struct {
	Country string // canonical name when geo knows it, else HMA's token spaced out
	CC      string // alpha-2, "" when geo can't resolve the country token
	Region  string // US state / AU state when present, else ""
	City    string
	Proto   string // "udp" or "tcp"
	Virtual bool   // "-VirtualUSA" style profiles exit elsewhere than they claim
	Path    string // path relative to configDir()
}

var (
	serverCache    []hmaServer
	serverCacheMu  sync.RWMutex
	activeServer   *hmaServer
	activeLocation string
	activeMu       sync.RWMutex
	loggedIn       bool

	// _LOC1S12 — HMA's datacenter/server ordinal suffix on a city.
	locSuffixRe = regexp.MustCompile(`_LOC\d+S\d+$`)
	// -VirtualUSA / -VirtualUK — a profile whose exit is virtually
	// located elsewhere than the city it is filed under.
	virtualRe = regexp.MustCompile(`-?Virtual[A-Za-z]+$`)
	// Lower-to-upper boundary inside a CamelCase token: LosAngeles →
	// Los Angeles, UnitedArabEmirates → United Arab Emirates. "USA"
	// and "WashingtonDC" keep their capitals together.
	camelRe = regexp.MustCompile(`([a-z])([A-Z])`)
	// Lower-case particles HMA glues onto the preceding word:
	// "Antiguaand Barbuda", "Republicofthe Congo", "Saint Kittsand
	// Nevis". Only split when another word follows (the trailing
	// space), so "Poland" / "Thailand" standing alone are untouched.
	particleRe = regexp.MustCompile(`([a-z])(and|of)(the)? `)

	// Bare "auth-user-pass" (no file argument) — HMA ships it in
	// every profile; rewritten to point at our credentials file.
	authUserPassRe = regexp.MustCompile(`(?m)^auth-user-pass\s*$`)
	// ns-cert-type was REMOVED in OpenVPN 2.5: a profile carrying it
	// makes the daemon refuse to start. remote-cert-tls is the
	// drop-in replacement (same server-cert EKU check).
	nsCertTypeRe = regexp.MustCompile(`(?m)^ns-cert-type\s+server\s*$`)
	// Directives OpenVPN 2.6 / OpenSSL 3 reject or that only add log
	// noise — same list ipvanish strips, for the same reasons.
	deprecatedDirectivesRe = regexp.MustCompile(`(?m)^(keysize|comp-lzo|cipher|tls-cipher|data-ciphers|data-ciphers-fallback)\b.*$`)
)

func init() {
	provider.Registry[name] = HideMyAss{}
}

func configDir() string {
	if dir := os.Getenv("HIDEMYASS_CONFIG_DIR"); dir != "" {
		return dir
	}
	return defaultConfigDir
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

// spaceCamel turns HMA's CamelCase tokens into spaced names:
// "SaintPetersburg" → "Saint Petersburg", "USA" → "USA",
// "AntiguaandBarbuda" → "Antigua and Barbuda".
func spaceCamel(s string) string {
	s = camelRe.ReplaceAllString(s, "$1 $2")
	s = particleRe.ReplaceAllString(s, "$1 $2 $3 ")
	return strings.Join(strings.Fields(s), " ")
}

// parsePath turns a profile path (relative to the config dir) into an
// hmaServer, or reports false when it doesn't follow HMA's naming.
// The protocol comes from the ".UDP"/".TCP" filename suffix or, in
// the directory layout, from the parent directory name; profiles
// that state neither default to UDP (HMA's own default).
func parsePath(rel string) (hmaServer, bool) {
	base := filepath.Base(rel)
	if !strings.HasSuffix(base, ".ovpn") {
		return hmaServer{}, false
	}
	stem := strings.TrimSuffix(base, ".ovpn")

	proto := ""
	if dir := strings.ToLower(filepath.Base(filepath.Dir(rel))); dir == "udp" || dir == "tcp" {
		proto = dir
	}
	for _, p := range []string{".UDP", ".TCP", ".udp", ".tcp"} {
		if strings.HasSuffix(stem, p) {
			proto = strings.ToLower(strings.TrimPrefix(p, "."))
			stem = strings.TrimSuffix(stem, p)
			break
		}
	}
	if proto == "" {
		proto = "udp"
	}

	segs := strings.Split(stem, ".")
	if len(segs) == 0 || segs[0] == "" {
		return hmaServer{}, false
	}

	countryTok := strings.ReplaceAll(segs[0], "`", "'")
	region, city := "", ""
	switch {
	case len(segs) == 1:
		// "Luxembourg_LOC1S1" — city-less country profile.
		countryTok = locSuffixRe.ReplaceAllString(countryTok, "")
	case len(segs) == 2:
		city = segs[1]
	default:
		// Country.Region.City — anything past the region belongs to
		// the city ("USA.Missouri.St.Louis_LOC1S1").
		region = spaceCamel(segs[1])
		city = strings.Join(segs[2:], ".")
	}

	virtual := false
	if city != "" {
		city, virtual = stripCity(city)
	}
	country, cc := resolveCountry(countryTok)
	if country == "" {
		return hmaServer{}, false
	}
	return hmaServer{
		Country: country,
		CC:      cc,
		Region:  region,
		City:    city,
		Proto:   proto,
		Virtual: virtual,
		Path:    rel,
	}, true
}

// stripCity removes the _LOCnSm ordinal and the -VirtualXX marker and
// spaces out the CamelCase city name.
func stripCity(city string) (string, bool) {
	city = locSuffixRe.ReplaceAllString(city, "")
	virtual := false
	if virtualRe.MatchString(city) {
		virtual = true
		city = virtualRe.ReplaceAllString(city, "")
	}
	city = strings.Trim(spaceCamel(city), " -")
	return city, virtual
}

// resolveCountry maps HMA's country token to the canonical geo name
// and alpha-2 code. Tokens geo doesn't know keep their spaced-out
// spelling with an empty code — still connectable, never preferred by
// the region walk.
func resolveCountry(tok string) (string, string) {
	spaced := spaceCamel(tok)
	if spaced == "" {
		return "", ""
	}
	if cc, ok := geo.Alpha2FromName(spaced); ok {
		if canonical, ok := geo.CountryName(cc); ok {
			return canonical, cc
		}
		return spaced, cc
	}
	return spaced, ""
}

func loadServers() ([]hmaServer, error) {
	serverCacheMu.RLock()
	if len(serverCache) > 0 {
		cached := append([]hmaServer(nil), serverCache...)
		serverCacheMu.RUnlock()
		return cached, nil
	}
	serverCacheMu.RUnlock()

	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()
	if len(serverCache) > 0 {
		return append([]hmaServer(nil), serverCache...), nil
	}

	servers, err := scanConfigDir(configDir())
	if err != nil {
		return nil, err
	}
	serverCache = servers
	shared.Debugf("HideMyAss: loaded %d OpenVPN profiles", len(servers))
	return append([]hmaServer(nil), servers...), nil
}

// scanConfigDir walks dir (recursively, so a UDP/ + TCP/ layout works)
// and parses every .ovpn profile except our own rewritten active one.
func scanConfigDir(dir string) ([]hmaServer, error) {
	var servers []hmaServer
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".ovpn") || d.Name() == activeConfigName {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		srv, ok := parsePath(rel)
		if !ok {
			shared.Debugf("HideMyAss: skipping unparseable %s", rel)
			return nil
		}
		servers = append(servers, srv)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", dir, err)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no HMA OpenVPN profiles found in %s", dir)
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Path < servers[j].Path })
	return servers, nil
}

// findServers matches a Locations() entry (country name), an alpha-2
// code or a city, case-insensitively. When a location has both UDP
// and TCP profiles only the UDP ones are offered — HMA's default and
// the cheaper transport under our MTU clamp.
func findServers(servers []hmaServer, location string) []hmaServer {
	var matches []hmaServer
	want := strings.ToLower(strings.TrimSpace(location))
	for _, s := range servers {
		if want == "" ||
			strings.ToLower(s.Country) == want ||
			(s.CC != "" && strings.ToLower(s.CC) == want) ||
			strings.ToLower(s.City) == want {
			matches = append(matches, s)
		}
	}
	var udp []hmaServer
	for _, s := range matches {
		if s.Proto == "udp" {
			udp = append(udp, s)
		}
	}
	if len(udp) > 0 {
		return udp
	}
	return matches
}

func pickRandomServer(servers []hmaServer) *hmaServer {
	if len(servers) == 0 {
		return nil
	}
	s := servers[rand.Intn(len(servers))]
	return &s
}

func writeCredentials(user, pass string) (string, error) {
	return shared.WriteUserPassFile(configDir(), credentialsName, user, pass)
}

// rewriteProfile adapts an HMA profile to OpenVPN 2.6:
//   - auth-user-pass → our credentials file
//   - ns-cert-type server → remote-cert-tls server (removed directive)
//   - legacy cipher/compression directives stripped, then a
//     data-ciphers list that still admits AES-CBC appended: HMA's
//     profiles name no cipher, and its older edges negotiate CBC
//     only — without the fallback OpenVPN 2.6's GCM-only default
//     fails the data-channel negotiation after a successful TLS
//     handshake.
func rewriteProfile(raw, credentialsFile string) string {
	out := authUserPassRe.ReplaceAllString(raw, "auth-user-pass "+credentialsFile)
	out = nsCertTypeRe.ReplaceAllString(out, "remote-cert-tls server")
	out = deprecatedDirectivesRe.ReplaceAllString(out, "")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-128-CBC\n"
	out += "data-ciphers-fallback AES-256-CBC\n"
	return out
}

func writeActiveConfig(server *hmaServer, credentialsFile string) (string, error) {
	src := filepath.Join(configDir(), server.Path)
	raw, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", src, err)
	}
	dst := filepath.Join(configDir(), activeConfigName)
	if err := os.WriteFile(dst, []byte(rewriteProfile(string(raw), credentialsFile)), 0600); err != nil {
		return "", fmt.Errorf("failed to write active config: %w", err)
	}
	return dst, nil
}

// isOpenVPNConnected reports whether the redirect-gateway push has
// taken effect — a route lookup for a public address resolves via
// tun0 in the MAIN namespace. See ipvanish.go for why the looser
// "any tun0 route" check fires too early for the exit-IP contract.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev tun0 ")
}

// ActiveLocation returns the verbatim Locations() entry passed to
// Connect so a block/allow list round-trips; per-server detail is on
// Status.Region.
func (h HideMyAss) ActiveLocation(ctx context.Context) string {
	if activeServer == nil {
		return ""
	}
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (h HideMyAss) Connect(ctx context.Context, location string) provider.Status {
	user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("HideMyAss: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}

	servers, err := loadServers()
	if err != nil {
		shared.Debugf("HideMyAss: failed to load servers: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}

	matches := findServers(servers, location)
	if len(matches) == 0 {
		shared.Debugf("HideMyAss: no servers found for location: %s", location)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	server := pickRandomServer(matches)
	credFile, err := writeCredentials(user, pass)
	if err != nil {
		shared.Debugf("HideMyAss: failed to write credentials: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	if _, err := writeActiveConfig(server, credFile); err != nil {
		shared.Debugf("HideMyAss: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	// Main namespace (RunCmd, not a netns variant) so tun0 becomes the
	// default route the in-process CONNECT proxy dials through; MTU
	// clamp below the pod MTU so the TLS handshake's UDP packets are
	// not dropped on the path — both as in ipvanish.go.
	if _, err := shared.RunCmd(ctx, "openvpn",
		"--cd", configDir(),
		"--config", activeConfigName,
		"--tun-mtu", "1320",
		"--mssfix", "1280",
		"--daemon"); err != nil {
		shared.Debugf("HideMyAss: failed to start openvpn: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	for j := 0; j < 60; j++ {
		time.Sleep(500 * time.Millisecond)
		if isOpenVPNConnected() {
			activeServer = server
			activeMu.Lock()
			activeLocation = location
			activeMu.Unlock()
			return h.Status(ctx)
		}
	}

	shared.Debugf("HideMyAss: connection timeout for %s", server.Path)
	return provider.Status{Connected: false, Provider: name, Location: location}
}

func (h HideMyAss) Connected(ctx context.Context) bool {
	return isOpenVPNConnected()
}

func (h HideMyAss) Disconnect(ctx context.Context) error {
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

func (h HideMyAss) Locations(ctx context.Context) []string {
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

func (h HideMyAss) LoggedIn(ctx context.Context) bool { return loggedIn }

func (h HideMyAss) Login(ctx context.Context) error {
	if _, _, err := getCredentials(); err != nil {
		return err
	}
	if _, err := loadServers(); err != nil {
		return err
	}
	loggedIn = true
	return nil
}

func (h HideMyAss) Logout(ctx context.Context) error {
	loggedIn = false
	return nil
}

func (h HideMyAss) Status(ctx context.Context) provider.Status {
	if !h.Connected(ctx) {
		return provider.Status{Connected: false, Provider: name}
	}
	status := provider.Status{
		Connected: true,
		Location:  h.ActiveLocation(ctx),
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
	parts := []string{activeServer.Country}
	if activeServer.Region != "" {
		parts = append(parts, activeServer.Region)
	}
	if activeServer.City != "" {
		parts = append(parts, activeServer.City)
	}
	return strings.Join(parts, " - ")
}

func (h HideMyAss) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, "openvpn", "--version")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0]), nil
}
