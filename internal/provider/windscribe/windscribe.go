// Package windscribe drives Windscribe over OpenVPN directly (no provider
// daemon). One owned openvpn child per connection, supervised over a
// management socket (internal/shared/ovpn, as ipvanish / veepn /
// protonvpn): the password travels over the socket, a node that refuses
// the credentials is reported as such (Status.AuthFailed) instead of
// timing out like a dead server, the tunnel comes up on a fixed
// tun-windscribe and Disconnect stops exactly that process.
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
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
	"github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

const (
	name          = "windscribe"
	defaultRunDir = "/run/windscribe"
	serverListURL = "https://assets.windscribe.com/serverlist/openvpn/1/0"
	// tunnelInterface is the fixed tun name the tunnel comes up on
	// (15 characters is the kernel limit).
	tunnelInterface = "tun-windscribe"
	// connectTimeout bounds one attempt: management startup, TLS
	// handshake and the CONNECTED state (the old route poll gave up
	// after 30 s).
	connectTimeout = 30 * time.Second
	// routeTimeout bounds the wait for the pushed redirect-gateway to
	// become the main-namespace default route after CONNECTED.
	routeTimeout = 10 * time.Second
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
	serverCache   []location
	serverCacheMu sync.RWMutex
	activeMu      sync.RWMutex
	current       *active
	loggedIn      bool
)

// startTunnel launches the owned openvpn; tests replace it.
var startTunnel = ovpn.Start

// active is the owned tunnel and where it goes.
type active struct {
	tunnel   *ovpn.Tunnel
	location string
	hostname string
}

type Windscribe struct{}

func init() {
	provider.Registry[name] = Windscribe{}
	accounts.RegisterLegacyShim(name, accounts.LegacyEnvFields(map[string]string{
		accounts.FieldUsername: "WINDSCRIBE_USERNAME",
		accounts.FieldPassword: "WINDSCRIBE_PASSWORD",
	}))
}

func runDir() string {
	if d := os.Getenv("WINDSCRIBE_RUN_DIR"); d != "" {
		return d
	}
	return defaultRunDir
}

func getCredentials() (user, pass string, err error) {
	acct, err := accounts.Current(name)
	if err != nil {
		return "", "", err
	}
	user, err = acct.Require(accounts.FieldUsername)
	if err != nil {
		return "", "", err
	}
	pass, err = acct.Require(accounts.FieldPassword)
	if err != nil {
		return "", "", err
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

// buildOpenVPNConfig renders the config for node n. socket is the
// management socket the owned openvpn answers on.
func buildOpenVPNConfig(n node, socket string) (string, error) {
	if !ovpn.ValidSocket(socket) {
		return "", errors.New("invalid Windscribe management socket path")
	}
	// No verify-x509-name: Windscribe's .whiskergalaxy.com node hostnames
	// don't map 1:1 to server cert CNs (a name can route to a differently-
	// named physical server, e.g. tw-015.whiskergalaxy.com → cert
	// tpe-166.windscribe.com), so a derived name fails the check.
	// remote-cert-tls server still validates the peer is a server cert
	// signed by Windscribe's CA, which is the protection we need.
	//
	// The transport and data-channel directives are the ones the
	// --daemon version ran with; only the credential, interface and
	// lifecycle lines changed with the move to the owned process.
	return fmt.Sprintf(`client
dev %s
dev-type tun
proto udp
remote %s 443
nobind
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
connect-retry-max 1
%s<ca>
%s
</ca>
<tls-auth>
%s
</tls-auth>
`, tunnelInterface, n.Hostname, ovpn.Directives(socket),
		strings.TrimSpace(embeddedCA), strings.TrimSpace(embeddedTLSAuth)), nil
}

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
		shared.Debugf("Windscribe: %v", err)
	}
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
	failed := provider.Status{Connected: false, Provider: name, Location: locationName}
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
		return failed
	}
	n := loc.Nodes[rand.Intn(len(loc.Nodes))]

	// One tunnel at a time: drop whatever we own before dialing.
	disconnect(ctx)

	tunnel, err := startTunnel(ctx, ovpn.Options{Name: "Windscribe", RunDir: runDir(), User: user, Pass: pass, Timeout: connectTimeout},
		func(socket string) ([]byte, error) {
			cfg, err := buildOpenVPNConfig(n, socket)
			return []byte(cfg), err
		})
	if errors.Is(err, ovpn.ErrAuthFailed) {
		// The credential is shared by every pod; when one node refuses
		// it the runtime skips this location and connects elsewhere.
		shared.Debugf("Windscribe: %s: %v", n.Hostname, err)
		failed.AuthFailed = true
		return failed
	}
	if err != nil {
		shared.Debugf("Windscribe: %s: %v", n.Hostname, err)
		return failed
	}
	if !waitForRoute(ctx, tunnel) {
		shared.Debugf("Windscribe: %s: connected but the default route never moved to %s", n.Hostname, tunnelInterface)
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
		_ = tunnel.Stop(stopCtx)
		cancel()
		return failed
	}
	activeMu.Lock()
	current = &active{tunnel: tunnel, location: loc.Name, hostname: n.Hostname}
	activeMu.Unlock()
	return w.Status(ctx)
}

func (Windscribe) Disconnect(ctx context.Context) error {
	disconnect(ctx)
	return nil
}

func (Windscribe) Connected(context.Context) bool {
	activeMu.RLock()
	a := current
	activeMu.RUnlock()
	return a != nil && a.tunnel.Address() != "" && isOpenVPNConnected()
}

func (w Windscribe) Status(ctx context.Context) provider.Status {
	if !w.Connected(ctx) {
		return provider.Status{Connected: false, Provider: name}
	}
	activeMu.RLock()
	a := current
	activeMu.RUnlock()
	return provider.Status{
		Connected: true,
		Provider:  name,
		Location:  a.location,
		Region:    a.location,
	}
}

func (Windscribe) ActiveLocation(context.Context) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil {
		return ""
	}
	return current.location
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
