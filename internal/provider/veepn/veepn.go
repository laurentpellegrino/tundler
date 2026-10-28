// Package veepn drives VeePN over OpenVPN directly (no provider daemon)
// with per-pod credentials: each pod owns one VeePN manual-config
// username/password (a Slots=1 account; the legacy shim keeps
// POD_<n>_VEEPN_USERNAME / POD_<n>_VEEPN_PASSWORD working), because every
// device credential consumes one of the account's connection slots.
//
// VeePN's per-location OpenVPN configs are NOT templatable: every one of
// the ~135 locations is fully self-contained, carrying its OWN embedded
// CA + tls-auth key + the ONE server IP of that location. So the upstream
// .ovpn files are baked into the image as they are (a zip from the
// `veepn-configs` GitHub release, see docker/providers/veepn/install.sh
// and .github/workflows/update-veepn-configs.yml) and Connect picks the
// chosen location's file, keeps its transport and keys, and replaces
// only the credential and lifecycle directives.
//
// One owned openvpn child per connection, supervised over a management
// socket (internal/shared/ovpn): password over the socket, AUTH_FAILED
// classified as an auth failure, a fixed tun interface, no process
// leaks. udp is tried first, tcp is the fallback for the same location.
//
// One IP per location means the whole provider has ~135 exits: a target
// that bans them one by one exhausts the pool, and nothing in the
// provider can change that — only a refreshed config set with rotated
// addresses or fewer rotations per account can.
package veepn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	name             = "veepn"
	defaultConfigDir = "/etc/veepn/configs"
	defaultRunDir    = "/run/veepn"
	// tunnelInterface is the fixed tun name the tunnel comes up on
	// (15 characters is the kernel limit).
	tunnelInterface = "tun-veepn"
	// connectTimeout bounds one openvpn attempt: management startup,
	// TLS handshake and the CONNECTED state.
	connectTimeout = 35 * time.Second
	// routeTimeout bounds the wait for the pushed redirect-gateway to
	// become the main-namespace default route after CONNECTED.
	routeTimeout = 10 * time.Second
)

var (
	// Upstream filename format: <location>.<proto>.veepn.com.ovpn
	// e.g. ae.udp.veepn.com.ovpn, au-nsw.tcp.veepn.com.ovpn.
	filenameRe = regexp.MustCompile(`^(.+)\.(udp|tcp)\.veepn\.com\.ovpn$`)
	// Directives dropped from the vendor config before ours are
	// appended: credentials come over the management socket, the
	// interface is pinned, verbosity, lifecycle and packet size are ours.
	droppedDirectiveRe = regexp.MustCompile(`(?m)^[ \t]*(auth-user-pass|dev|dev-type|management[a-z-]*|verb|daemon|log|log-append|auth-retry|auth-nocache|connect-retry|connect-retry-max|connect-timeout|tun-mtu-extra|tun-mtu|mssfix)\b.*\n?`)
	// Inline blocks (<ca>, <tls-auth>) are kept verbatim.
	inlineBlockRe = regexp.MustCompile(`(?s)<([a-z-]+)>.*?</[a-z-]+>`)
	remoteRe      = regexp.MustCompile(`(?m)^[ \t]*remote[ \t]+\S+`)

	serverCache   []veepnServer
	serverCacheMu sync.RWMutex

	activeMu sync.RWMutex
	current  *active
	loggedIn bool
)

// veepnServer is one baked .ovpn (one location, one protocol).
type veepnServer struct {
	Location string // e.g. "ae", "au-nsw", "albania"
	Proto    string // "udp" | "tcp"
	Filename string
}

// active is the current connection: the owned openvpn child plus what
// it was asked to connect to.
type active struct {
	tunnel   *ovpn.Tunnel
	server   *veepnServer
	location string
}

type VeePN struct{}

func init() {
	provider.Registry[name] = VeePN{}
	accounts.RegisterLegacyShim(name, accounts.LegacyPerPodEnv("POD_%d_VEEPN_", map[string]string{
		accounts.FieldUsername: "USERNAME",
		accounts.FieldPassword: "PASSWORD",
	}))
}

func configDir() string {
	if d := os.Getenv("VEEPN_CONFIG_DIR"); d != "" {
		return d
	}
	return defaultConfigDir
}

// runDir holds the per-connection config and management socket
// (tmpfs in the image; Unix socket paths are limited to 107 bytes).
func runDir() string {
	if d := os.Getenv("VEEPN_RUN_DIR"); d != "" {
		return d
	}
	return defaultRunDir
}

// getCredentials returns this pod's VeePN manual-config username/password
// (its Slots=1 account; POD_<n>_VEEPN_* via the legacy shim).
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

// loadServers indexes the baked .ovpn files, cached for the process
// lifetime (the directory is static — refreshed only by an image rebuild).
func loadServers() ([]veepnServer, error) {
	serverCacheMu.RLock()
	if len(serverCache) > 0 {
		cached := append([]veepnServer(nil), serverCache...)
		serverCacheMu.RUnlock()
		return cached, nil
	}
	serverCacheMu.RUnlock()

	serverCacheMu.Lock()
	defer serverCacheMu.Unlock()
	if len(serverCache) > 0 {
		return append([]veepnServer(nil), serverCache...), nil
	}

	dir := configDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", dir, err)
	}
	var servers []veepnServer
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := filenameRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		servers = append(servers, veepnServer{Location: m[1], Proto: m[2], Filename: e.Name()})
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no VeePN OpenVPN configs found in %s", dir)
	}
	serverCache = servers
	shared.Debugf("VeePN: loaded %d OpenVPN configs", len(servers))
	return append([]veepnServer(nil), servers...), nil
}

// candidates returns the location's configs in try order: udp first,
// tcp as the fallback.
func candidates(servers []veepnServer, location string) []*veepnServer {
	want := strings.ToLower(strings.TrimSpace(location))
	var udp, tcp *veepnServer
	for i := range servers {
		if strings.ToLower(servers[i].Location) != want {
			continue
		}
		s := servers[i]
		if s.Proto == "udp" {
			udp = &s
		} else {
			tcp = &s
		}
	}
	var out []*veepnServer
	for _, s := range []*veepnServer{udp, tcp} {
		if s != nil {
			out = append(out, s)
		}
	}
	return out
}

// openVPNConfig turns a vendor .ovpn into the config this provider
// runs: transport, keys and server kept, credential and lifecycle
// handling replaced by ours. socket is the management socket path.
func openVPNConfig(vendor []byte, socket string) ([]byte, error) {
	if !ovpn.ValidSocket(socket) {
		return nil, errors.New("invalid VeePN management socket path")
	}
	text := strings.ReplaceAll(string(vendor), "\r\n", "\n")
	if !remoteRe.MatchString(text) {
		return nil, errors.New("VeePN config has no remote")
	}
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
	// --tun-mtu / --mssfix clamp packet size below the k8s pod MTU
	// (1370 on Talos/Cilium), as the other OpenVPN providers do. The
	// vendor's tun-mtu 1500 / mssfix 1450 let the login, the management
	// socket and small probes through, so the tunnel looked Ready, while
	// every full-size page fetch stalled until the client's read timeout.
	ours := "\n# --- tundler ---\ndev " + tunnelInterface + "\ndev-type tun\n" + ovpn.Directives(socket) +
		"connect-retry-max 1\nconnect-timeout 15\ntun-mtu 1320\nmssfix 1280\nverb 0\n"
	return []byte(text + ours), nil
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

// ---- VPNProvider ------------------------------------------------------

// Login is a no-op auth check for OpenVPN-direct: it just verifies this
// pod's credentials are present and configs are baked.
func (v VeePN) Login(ctx context.Context) error {
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

func (VeePN) Logout(context.Context) error {
	activeMu.Lock()
	loggedIn = false
	activeMu.Unlock()
	return nil
}

func (VeePN) LoggedIn(context.Context) bool {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return loggedIn
}

func (VeePN) Locations(context.Context) []string {
	servers, err := loadServers()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var locations []string
	for _, s := range servers {
		if seen[s.Location] {
			continue
		}
		seen[s.Location] = true
		locations = append(locations, s.Location)
	}
	sort.Strings(locations)
	return locations
}

func (v VeePN) Connect(ctx context.Context, location string) provider.Status {
	failed := provider.Status{Connected: false, Provider: name, Location: location}
	user, pass, err := getCredentials()
	if err != nil {
		shared.Debugf("VeePN: %v", err)
		return failed
	}
	servers, err := loadServers()
	if err != nil {
		shared.Debugf("VeePN: %v", err)
		return failed
	}
	tries := candidates(servers, location)
	if len(tries) == 0 {
		shared.Debugf("VeePN: no config for location %q", location)
		return failed
	}

	// One tunnel at a time: drop whatever we own before dialing.
	disconnect(ctx)

	for _, server := range tries {
		if ctx.Err() != nil {
			break
		}
		vendor, err := os.ReadFile(filepath.Join(configDir(), server.Filename))
		if err != nil {
			shared.Debugf("VeePN: read %s: %v", server.Filename, err)
			continue
		}
		tunnel, err := ovpn.Start(ctx, ovpn.Options{Name: "VeePN", RunDir: runDir(), CD: configDir(), User: user, Pass: pass, Timeout: connectTimeout},
			func(socket string) ([]byte, error) { return openVPNConfig(vendor, socket) })
		if errors.Is(err, ovpn.ErrAuthFailed) {
			// This pod's device credential was rejected: another
			// transport cannot help. Report it so the runtime holds.
			shared.Debugf("VeePN: %s: %v", server.Filename, err)
			failed.AuthFailed = true
			return failed
		}
		if err != nil {
			shared.Debugf("VeePN: %s: %v", server.Filename, err)
			continue
		}
		if !waitForRoute(ctx, tunnel) {
			shared.Debugf("VeePN: %s: connected but the default route never moved to %s", server.Filename, tunnelInterface)
			stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
			_ = tunnel.Stop(stopCtx)
			cancel()
			continue
		}
		activeMu.Lock()
		current = &active{tunnel: tunnel, server: server, location: location}
		activeMu.Unlock()
		return v.Status(ctx)
	}
	return failed
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
		shared.Debugf("VeePN: %v", err)
	}
}

func (VeePN) Disconnect(ctx context.Context) error {
	disconnect(ctx)
	return nil
}

func (VeePN) Connected(context.Context) bool {
	activeMu.RLock()
	a := current
	activeMu.RUnlock()
	return a != nil && a.tunnel.Address() != "" && isOpenVPNConnected()
}

func (v VeePN) Status(ctx context.Context) provider.Status {
	if !v.Connected(ctx) {
		return provider.Status{Connected: false, Provider: name}
	}
	activeMu.RLock()
	a := current
	activeMu.RUnlock()
	status := provider.Status{
		Connected: true,
		Provider:  name,
		Location:  a.location,
		Region:    strings.ToUpper(a.location) + " (" + a.server.Proto + ")",
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

func (VeePN) ActiveLocation(context.Context) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if current == nil {
		return ""
	}
	return current.location
}

func (VeePN) Version(ctx context.Context) (string, error) {
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
