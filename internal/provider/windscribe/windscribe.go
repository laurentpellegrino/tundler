// Package windscribe drives Windscribe over OpenVPN directly (no provider
// daemon), the same OpenVPN-direct shape as ovpn / purevpn / cyberghost.
//
// Windscribe is the friendliest provider to automate:
//
//   - The server list is a PUBLIC, no-auth JSON API
//     (assets.windscribe.com/serverlist/openvpn/1/0) — no Cloudflare, no
//     login — so the provider fetches it live at Login() and falls back to
//     an embedded snapshot if the API is unreachable. No daily workflow.
//   - The CA + tls-auth are static/shared across every Windscribe config
//     (embedded here).
//   - One shared OpenVPN credential (WINDSCRIBE_USERNAME/PASSWORD, distinct
//     from the account login) with UNLIMITED simultaneous connections, so
//     every pod shares it and there's no per-account slot ceiling.
//
// Each location in the API carries a set of nodes; we pick a random node
// per Connect() and build the .ovpn from a template: remote
// <node>.whiskergalaxy.com:443/udp with verify-x509-name
// <node>.windscribe.com (the cert CN uses the .windscribe.com identity
// even though the A-record host is .whiskergalaxy.com), AES-256-GCM /
// SHA512, tls-auth key-direction 1.
package windscribe

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
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
	name             = "windscribe"
	defaultConfigDir = "/etc/windscribe/openvpn"
	activeConfigName = "active.ovpn"
	credentialsName  = "auth.txt"
	serverListURL    = "https://assets.windscribe.com/serverlist/openvpn/1/0"
)

//go:embed ca.crt
var embeddedCA string

//go:embed ta.key
var embeddedTLSAuth string

//go:embed servers.json
var embeddedServers []byte

type node struct {
	Hostname string `json:"hostname"`
}

type location struct {
	Name        string `json:"name"`
	ShortName   string `json:"short_name"`
	CountryCode string `json:"country_code"`
	PremiumOnly int    `json:"premium_only"`
	Nodes       []node `json:"nodes"`
}

type serverList struct {
	Data []location `json:"data"`
}

var (
	serverCache    []location
	serverCacheMu  sync.RWMutex
	activeLocation string
	activeMu       sync.RWMutex
	loggedIn       bool
)

type Windscribe struct{}

func init() { provider.Registry[name] = Windscribe{} }

func configDir() string {
	if d := os.Getenv("WINDSCRIBE_CONFIG_DIR"); d != "" {
		return d
	}
	return defaultConfigDir
}

func getCredentials() (user, pass string, err error) {
	user = strings.TrimSpace(os.Getenv("WINDSCRIBE_USERNAME"))
	pass = strings.TrimSpace(os.Getenv("WINDSCRIBE_PASSWORD"))
	if user == "" || pass == "" {
		return "", "", fmt.Errorf("WINDSCRIBE_USERNAME and WINDSCRIBE_PASSWORD environment variables must be set")
	}
	return user, pass, nil
}

// loadServers returns the location list, fetched live from the public API
// (cached for the process lifetime) and falling back to the embedded
// snapshot if the API is unreachable.
func loadServers() ([]location, error) {
	serverCacheMu.RLock()
	if len(serverCache) > 0 {
		cached := append([]location(nil), serverCache...)
		serverCacheMu.RUnlock()
		return cached, nil
	}
	serverCacheMu.RUnlock()

	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()
	if len(serverCache) > 0 {
		return append([]location(nil), serverCache...), nil
	}

	locs, err := fetchLiveServers()
	if err != nil {
		shared.Debugf("Windscribe: live server list fetch failed (%v); using embedded fallback", err)
		var sl serverList
		if e := json.Unmarshal(embeddedServers, &sl); e != nil {
			return nil, fmt.Errorf("parse embedded servers: %w", e)
		}
		locs = sl.Data
	}

	var out []location
	for _, l := range locs {
		if len(l.Nodes) > 0 {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no Windscribe locations with nodes")
	}
	serverCache = out
	shared.Debugf("Windscribe: loaded %d locations", len(out))
	return append([]location(nil), out...), nil
}

func fetchLiveServers() ([]location, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverListURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var sl serverList
	if err := json.NewDecoder(resp.Body).Decode(&sl); err != nil {
		return nil, err
	}
	return sl.Data, nil
}

func findLocation(locs []location, want string) *location {
	w := strings.ToLower(strings.TrimSpace(want))
	for i := range locs {
		l := locs[i]
		if strings.ToLower(l.Name) == w || strings.ToLower(l.ShortName) == w {
			return &locs[i]
		}
	}
	return nil
}

func buildOpenVPNConfig(n node, authPath string) string {
	// No verify-x509-name: Windscribe's .whiskergalaxy.com node hostnames
	// don't map 1:1 to server cert CNs (a name can route to a differently-
	// named physical server, e.g. tw-015.whiskergalaxy.com → cert
	// tpe-166.windscribe.com), so a derived name fails the check.
	// remote-cert-tls server still validates the peer is a server cert
	// signed by Windscribe's CA, which is the protection we need.
	return fmt.Sprintf(`client
dev tun
proto udp
remote %s 443
nobind
auth-user-pass %s
resolv-retry infinite
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-256-CBC:AES-128-GCM
auth SHA512
verb 2
mute-replay-warnings
remote-cert-tls server
persist-key
persist-tun
key-direction 1
<ca>
%s
</ca>
<tls-auth>
%s
</tls-auth>
`, n.Hostname, authPath,
		strings.TrimSpace(embeddedCA), strings.TrimSpace(embeddedTLSAuth))
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

func writeActiveConfig(n node, authPath string) (string, error) {
	dst := filepath.Join(configDir(), activeConfigName)
	if err := os.WriteFile(dst, []byte(buildOpenVPNConfig(n, authPath)), 0600); err != nil {
		return "", fmt.Errorf("write active config: %w", err)
	}
	return dst, nil
}

func isOpenVPNConnected() bool {
	out, err := shared.RunCmdSilent(context.Background(), "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return false
	}
	return strings.Contains(out, " dev tun0 ")
}

// ---- VPNProvider ------------------------------------------------------

func (Windscribe) Login(ctx context.Context) error {
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

func (Windscribe) Logout(context.Context) error {
	activeMu.Lock()
	loggedIn = false
	activeMu.Unlock()
	return nil
}

func (Windscribe) LoggedIn(context.Context) bool {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return loggedIn
}

func (Windscribe) Locations(context.Context) []string {
	locs, err := loadServers()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(locs))
	for _, l := range locs {
		out = append(out, l.Name)
	}
	sort.Strings(out)
	return out
}

func (w Windscribe) Connect(ctx context.Context, locationName string) provider.Status {
	user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("Windscribe: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	locs, err := loadServers()
	if err != nil {
		shared.Debugf("Windscribe: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	loc := findLocation(locs, locationName)
	if loc == nil || len(loc.Nodes) == 0 {
		shared.Debugf("Windscribe: no node for location %q", locationName)
		return provider.Status{Connected: false, Provider: name, Location: locationName}
	}
	n := loc.Nodes[rand.Intn(len(loc.Nodes))]

	authPath, err := writeCredentials(user, pass)
	if err != nil {
		shared.Debugf("Windscribe: write credentials: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: locationName}
	}
	if _, err := writeActiveConfig(n, authPath); err != nil {
		shared.Debugf("Windscribe: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: locationName}
	}

	if _, err := shared.RunCmd(ctx, "openvpn",
		"--cd", configDir(),
		"--config", activeConfigName,
		"--daemon"); err != nil {
		shared.Debugf("Windscribe: failed to start openvpn: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: locationName}
	}

	for j := 0; j < 60; j++ {
		time.Sleep(500 * time.Millisecond)
		if isOpenVPNConnected() {
			activeMu.Lock()
			activeLocation = loc.Name
			activeMu.Unlock()
			return w.Status(ctx)
		}
	}
	shared.Debugf("Windscribe: connection timeout for %s", n.Hostname)
	_, _ = shared.RunCmd(ctx, "pkill", "-SIGTERM", "openvpn")
	return provider.Status{Connected: false, Provider: name, Location: locationName}
}

func (Windscribe) Disconnect(ctx context.Context) error {
	_, _ = shared.RunCmd(ctx, "pkill", "-SIGTERM", "openvpn")
	for j := 0; j < 20; j++ {
		if !isOpenVPNConnected() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
	return nil
}

func (Windscribe) Connected(context.Context) bool { return isOpenVPNConnected() }

func (w Windscribe) Status(context.Context) provider.Status {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if activeLocation == "" {
		return provider.Status{Connected: false, Provider: name}
	}
	return provider.Status{
		Connected: true,
		Provider:  name,
		Location:  activeLocation,
		Region:    activeLocation,
	}
}

func (Windscribe) ActiveLocation(context.Context) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (Windscribe) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, "openvpn", "--version")
	if err != nil && out == "" {
		return "", err
	}
	first := out
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	return strings.TrimSpace(first), nil
}
