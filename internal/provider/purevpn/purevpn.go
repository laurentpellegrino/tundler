// Package purevpn drives PureVPN over OpenVPN directly (no provider
// daemon). One owned openvpn child per connection, supervised over a
// management socket (internal/shared/ovpn, as ovpn / cyberghost /
// windscribe): the password travels over the socket, a server that
// refuses the credentials is reported as such (Status.AuthFailed) instead
// of timing out like a dead server, the tunnel comes up on a fixed
// tun-purevpn and Disconnect stops exactly that process.
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
	"errors"
	"fmt"
	"math/rand"
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
	name          = "purevpn"
	serversFile   = "/etc/purevpn/servers.json"
	defaultRunDir = "/run/purevpn"
	// tunnelInterface is the fixed tun name the tunnel comes up on
	// (15 characters is the kernel limit).
	tunnelInterface = "tun-purevpn"
	// connectTimeout bounds one attempt: management startup, TLS
	// handshake and the CONNECTED state (the old route poll gave up
	// after 30 s).
	connectTimeout = 30 * time.Second
	// routeTimeout bounds the wait for the pushed redirect-gateway to
	// become the main-namespace default route after CONNECTED.
	routeTimeout = 10 * time.Second
)

//go:embed ca.crt
var embeddedCACert string

//go:embed ta.key
var embeddedTLSAuth string

type PureVPN struct{}

var (
	serverCache   []string // server slugs, e.g. "de2", "uswdc2"
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
	slug     string
	location string
}

func runDir() string {
	if d := os.Getenv("PUREVPN_RUN_DIR"); d != "" {
		return d
	}
	return defaultRunDir
}

func init() {
	provider.Registry[name] = PureVPN{}
	accounts.RegisterLegacyShim(name, accounts.LegacyEnvFields(map[string]string{
		accounts.FieldUsername: "PUREVPN_USERNAME",
		accounts.FieldPassword: "PUREVPN_PASSWORD",
	}))
}

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

// buildOpenVPNConfig renders the config from PureVPN's directives (UDP,
// AES-256-GCM, remote-cert-tls server, key-direction 1) with the embedded
// CA + tls-auth and the chosen server's remote. The Windows-only
// directives from the downloaded config (route-method, block-outside-dns,
// script-security) are dropped. The transport and data-channel directives
// are the ones the --daemon version ran with; the credential, interface,
// MTU clamp (formerly command-line flags) and lifecycle lines changed with
// the move to the owned process. socket is the management socket the
// owned openvpn answers on.
func buildOpenVPNConfig(slug, socket string) (string, error) {
	if !ovpn.ValidSocket(socket) {
		return "", errors.New("invalid PureVPN management socket path")
	}
	// --tun-mtu / --mssfix clamp packet size below the k8s pod MTU so
	// the TLS handshake's UDP packets aren't dropped (same values
	// ipvanish / ovpn use).
	return fmt.Sprintf(`client
dev %s
dev-type tun
proto udp
remote %s 1194
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
explicit-exit-notify
key-direction 1
tun-mtu 1320
mssfix 1280
connect-retry-max 1
%s<ca>
%s
</ca>
<tls-auth>
%s
</tls-auth>
`, tunnelInterface, slugHostname(slug), ovpn.Directives(socket),
		strings.TrimSpace(embeddedCACert), strings.TrimSpace(embeddedTLSAuth)), nil
}

// isOpenVPNConnected returns true once the redirect-gateway push has taken
// effect (a route lookup for a public address resolves via the tunnel
// interface, not eth0). Runs in the MAIN namespace, where the in-process
// CONNECT proxy dials.
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
		shared.Debugf("PureVPN: %v", err)
	}
}

func (p PureVPN) ActiveLocation(ctx context.Context) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil {
		return ""
	}
	return current.location
}

func activeSlug() string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil {
		return ""
	}
	return current.slug
}

func (p PureVPN) Connect(ctx context.Context, location string) provider.Status {
	failed := provider.Status{Connected: false, Provider: name, Location: location}
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
		return failed
	}
	slug := matches[rand.Intn(len(matches))]

	// One tunnel at a time: drop whatever we own before dialing.
	disconnect(ctx)

	tunnel, err := startTunnel(ctx, ovpn.Options{Name: "PureVPN", RunDir: runDir(), User: user, Pass: pass, Timeout: connectTimeout},
		func(socket string) ([]byte, error) {
			cfg, err := buildOpenVPNConfig(slug, socket)
			return []byte(cfg), err
		})
	if errors.Is(err, ovpn.ErrAuthFailed) {
		// The credential is shared by every pod; when one server
		// refuses it the runtime skips this location and connects
		// elsewhere.
		shared.Debugf("PureVPN: %s: %v", slugHostname(slug), err)
		failed.AuthFailed = true
		return failed
	}
	if err != nil {
		shared.Debugf("PureVPN: %s: %v", slugHostname(slug), err)
		return failed
	}
	if !waitForRoute(ctx, tunnel) {
		shared.Debugf("PureVPN: %s: connected but the default route never moved to %s", slugHostname(slug), tunnelInterface)
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
		_ = tunnel.Stop(stopCtx)
		cancel()
		return failed
	}
	activeMu.Lock()
	current = &active{tunnel: tunnel, slug: slug, location: location}
	activeMu.Unlock()
	return p.Status(ctx)
}

func (p PureVPN) Connected(ctx context.Context) bool {
	activeMu.RLock()
	a := current
	activeMu.RUnlock()
	return a != nil && a.tunnel.Address() != "" && isOpenVPNConnected()
}

func (p PureVPN) Disconnect(ctx context.Context) error {
	disconnect(ctx)
	return nil
}

// Daemonless marks the tunnel as an owned openvpn child (see
// provider.Daemonless).
func (PureVPN) Daemonless() {}

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

func (p PureVPN) LoggedIn(ctx context.Context) bool {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return loggedIn
}

func (p PureVPN) Login(ctx context.Context) error {
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

func (p PureVPN) Logout(ctx context.Context) error {
	activeMu.Lock()
	loggedIn = false
	activeMu.Unlock()
	return nil
}

func (p PureVPN) Status(ctx context.Context) provider.Status {
	if !p.Connected(ctx) {
		return provider.Status{Connected: false, Provider: name}
	}
	status := provider.Status{
		Connected: true,
		Location:  p.ActiveLocation(ctx),
		Region:    activeSlug(),
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
