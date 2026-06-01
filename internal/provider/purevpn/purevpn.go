// Package purevpn drives PureVPN over OpenVPN directly (no provider
// daemon), the same OpenVPN-direct shape as ovpn / cyberghost / fastvpn.
//
// Auth is a single shared username/password (PUREVPN_USERNAME/
// PUREVPN_PASSWORD from OpenBao vpn/purevpn) — PureVPN allows up to 10
// simultaneous connections on one credential, so the pods share it (no
// per-pod keys). The CA cert + tls-auth key are PureVPN's static, shared,
// non-secret material (identical in every server's config) and are
// embedded here; the per-server remote is built from the baked server-slug
// list (/etc/purevpn/servers.json, refreshed daily — see install.sh) as
// <slug>-auto-udp-qr.ptoserver.com.
package purevpn

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	name             = "purevpn"
	serversFile      = "/etc/purevpn/servers.json"
	configDir        = "/etc/purevpn/openvpn"
	activeConfigName = "active.ovpn"
	credentialsName  = "auth.txt"
)

//go:embed ca.crt
var embeddedCACert string

//go:embed ta.key
var embeddedTLSAuth string

type PureVPN struct{}

var (
	serverCache    []string // server slugs, e.g. "de2", "uswdc2"
	serverCacheMu  sync.RWMutex
	activeSlug     string
	activeLocation string
	activeMu       sync.RWMutex
	loggedIn       bool
)

func init() { provider.Registry[name] = PureVPN{} }

// slugHostname builds the OpenVPN remote for a server slug.
func slugHostname(slug string) string {
	return slug + "-auto-udp-qr.ptoserver.com"
}

// slugCountry returns the 2-letter country prefix of a slug (the slug
// always starts with an ISO-ish country code, e.g. de2→de, uswdc2→us).
func slugCountry(slug string) string {
	if len(slug) >= 2 {
		return slug[:2]
	}
	return slug
}

func getCredentials() (string, string, error) {
	user := os.Getenv("PUREVPN_USERNAME")
	pass := os.Getenv("PUREVPN_PASSWORD")
	if user == "" || pass == "" {
		return "", "", fmt.Errorf("PUREVPN_USERNAME and PUREVPN_PASSWORD environment variables must be set")
	}
	return user, pass, nil
}

// loadServers parses the baked slug list (a JSON array of strings), cached
// for the process lifetime (static — refreshed only by an image rebuild).
func loadServers() ([]string, error) {
	serverCacheMu.RLock()
	if len(serverCache) > 0 {
		cached := append([]string(nil), serverCache...)
		serverCacheMu.RUnlock()
		return cached, nil
	}
	serverCacheMu.RUnlock()

	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()
	if len(serverCache) > 0 {
		return append([]string(nil), serverCache...), nil
	}

	data, err := os.ReadFile(serversFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", serversFile, err)
	}
	var slugs []string
	if err := json.Unmarshal(data, &slugs); err != nil {
		return nil, fmt.Errorf("parse %s: %w", serversFile, err)
	}
	var cleaned []string
	for _, s := range slugs {
		if s = strings.TrimSpace(s); s != "" {
			cleaned = append(cleaned, s)
		}
	}
	if len(cleaned) == 0 {
		return nil, fmt.Errorf("no PureVPN servers in %s", serversFile)
	}
	sort.Strings(cleaned)
	serverCache = cleaned
	shared.Debugf("PureVPN: loaded %d servers from %s", len(cleaned), serversFile)
	return append([]string(nil), cleaned...), nil
}

// findServers filters slugs by country prefix (case-insensitive) or exact
// slug. Empty location returns all.
func findServers(slugs []string, location string) []string {
	if location == "" {
		return slugs
	}
	want := strings.ToLower(location)
	var matches []string
	for _, s := range slugs {
		if strings.ToLower(slugCountry(s)) == want || strings.ToLower(s) == want {
			matches = append(matches, s)
		}
	}
	return matches
}

func writeCredentials(user, pass string) (string, error) {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(configDir, credentialsName)
	if err := os.WriteFile(path, []byte(user+"\n"+pass+"\n"), 0600); err != nil {
		return "", err
	}
	return path, nil
}

// writeConfig builds the .ovpn from PureVPN's directives (UDP, AES-256-GCM,
// remote-cert-tls server, key-direction 1) with the embedded CA + tls-auth
// and the chosen server's remote. The Windows-only directives from the
// downloaded config (route-method, block-outside-dns, script-security) are
// dropped.
func writeConfig(slug, credFile string) (string, error) {
	config := fmt.Sprintf(`client
dev tun
proto udp
remote %s 1194
auth-user-pass %s
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
explicit-exit-notify
key-direction 1
<ca>
%s</ca>
<tls-auth>
%s</tls-auth>
`, slugHostname(slug), credFile, embeddedCACert, embeddedTLSAuth)

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(configDir, activeConfigName)
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	return path, nil
}

// isOpenVPNConnected returns true once the redirect-gateway push has taken
// effect (a route lookup for a public address resolves via tun0, not eth0).
// Same gate as ovpn / cyberghost / ipvanish; runs in the MAIN namespace.
func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev tun0 ")
}

func (p PureVPN) ActiveLocation(ctx context.Context) string {
	if activeSlug == "" {
		return ""
	}
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (p PureVPN) Connect(ctx context.Context, location string) provider.Status {
	user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("PureVPN: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	slugs, err := loadServers()
	if err != nil {
		shared.Debugf("PureVPN: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	matches := findServers(slugs, location)
	if len(matches) == 0 {
		shared.Debugf("PureVPN: no servers for location: %s", location)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	slug := matches[rand.Intn(len(matches))]

	credFile, err := writeCredentials(user, pass)
	if err != nil {
		shared.Debugf("PureVPN: write credentials: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	if _, err := writeConfig(slug, credFile); err != nil {
		shared.Debugf("PureVPN: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	// RunCmd (main ns) so openvpn + tun0 land in the pod's MAIN namespace
	// where the in-process CONNECT proxy lives. --tun-mtu/--mssfix clamp
	// packet size below the k8s pod MTU so the TLS handshake's UDP packets
	// aren't dropped (same values ipvanish/ovpn use).
	if _, err := shared.RunCmd(ctx, "openvpn",
		"--cd", configDir,
		"--config", activeConfigName,
		"--tun-mtu", "1320",
		"--mssfix", "1280",
		"--daemon"); err != nil {
		shared.Debugf("PureVPN: failed to start openvpn: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		if isOpenVPNConnected() {
			activeSlug = slug
			activeMu.Lock()
			activeLocation = location
			activeMu.Unlock()
			return p.Status(ctx)
		}
	}
	shared.Debugf("PureVPN: connection timeout for %s", slugHostname(slug))
	return provider.Status{Connected: false, Provider: name, Location: location}
}

func (p PureVPN) Connected(ctx context.Context) bool { return isOpenVPNConnected() }

func (p PureVPN) Disconnect(ctx context.Context) error {
	_, _ = shared.RunCmd(ctx, "pkill", "-SIGTERM", "openvpn")
	for i := 0; i < 20; i++ {
		if !isOpenVPNConnected() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	activeSlug = ""
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
	return nil
}

func (p PureVPN) Locations(ctx context.Context) []string {
	slugs, err := loadServers()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var locations []string
	for _, s := range slugs {
		cc := slugCountry(s)
		if cc == "" || seen[cc] {
			continue
		}
		seen[cc] = true
		locations = append(locations, cc)
	}
	sort.Strings(locations)
	return locations
}

func (p PureVPN) LoggedIn(ctx context.Context) bool { return loggedIn }

func (p PureVPN) Login(ctx context.Context) error {
	if _, _, err := getCredentials(); err != nil {
		return err
	}
	if _, err := loadServers(); err != nil {
		return err
	}
	loggedIn = true
	return nil
}

func (p PureVPN) Logout(ctx context.Context) error {
	loggedIn = false
	return nil
}

func (p PureVPN) Status(ctx context.Context) provider.Status {
	if !isOpenVPNConnected() {
		return provider.Status{Connected: false, Provider: name}
	}
	status := provider.Status{
		Connected: true,
		Location:  p.ActiveLocation(ctx),
		Region:    activeSlug,
		Provider:  name,
	}
	if out, err := shared.RunCmd(ctx, "curl", "-s", "--max-time", "5", "https://icanhazip.com"); err == nil {
		status.IP = strings.TrimSpace(out)
	}
	return status
}

func (p PureVPN) Version(ctx context.Context) (string, error) {
	slugs, err := loadServers()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("openvpn (%d servers)", len(slugs)), nil
}
