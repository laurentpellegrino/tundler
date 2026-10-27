package ipvanish

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/laurentpellegrino/tundler/internal/shared/warpproxy"
)

// One owned openvpn child per connection, supervised over a private Unix
// management socket. The process is a child of tundler-tunnel (so a
// crashed supervisor takes it down, see configureChild) and the account
// password travels over the socket, never through a file or the
// environment. Neither OpenVPN output nor management messages are
// forwarded to logs: both can carry the credentials.

// tunnelInterface is the fixed tun name the tunnel comes up on, so the
// connected check never confuses a stale interface from a previous
// attempt with the live one (15 characters is the kernel limit).
const tunnelInterface = "tun-ipvanish"

// errAuthFailed is OpenVPN's AUTH_FAILED: the server rejected the
// account's username/password. With IPVanish this is also what an
// anti-abuse suspension looks like (too many logins in a short window
// suspends the account for ~24 h, and every further login extends it),
// so the caller must stop logging in, not retry elsewhere.
var errAuthFailed = errors.New("IPVanish rejected the account credentials (AUTH_FAILED)")

var (
	// Directives dropped from the vendor config before ours are appended.
	//
	//   auth-user-pass — credentials come over the management socket.
	//   dev/dev-type   — pinned to tunnelInterface.
	//   management*, verb, daemon, log*, auth-retry, auth-nocache,
	//   redirect-gateway, persist-*, connect-*, mssfix, tun-mtu —
	//                    owned by the block below.
	//   keysize        — removed from OpenVPN 2.6, the daemon refuses
	//                    to start with it present.
	//   comp-lzo       — enables receive-side compression (the VORACLE
	//                    attack vector); OpenVPN 2.6 warns but starts.
	//   cipher AES-…   — ignored for the data channel by OpenVPN 2.6
	//                    (NCP negotiates it), only a deprecation warning.
	//   tls-cipher …   — THE invisible-failure directive. IPVanish pins
	//                    the TLS control channel to three TLS_*_CBC_SHA
	//                    suites that OpenSSL 3 disables at SecLevel 2.
	//                    Result: no cipher to offer, no Client Hello is
	//                    ever sent, the server hears silence — looks
	//                    identical to an IP block from our side.
	droppedDirectiveRe = regexp.MustCompile(`(?m)^[ \t]*(auth-user-pass|dev|dev-type|management[a-z-]*|verb|daemon|log|log-append|auth-retry|auth-nocache|redirect-gateway|persist-key|persist-tun|connect-retry|connect-retry-max|connect-timeout|mssfix|tun-mtu|keysize|comp-lzo|cipher|tls-cipher)\b.*\n?`)
	// Inline blocks (<ca>…</ca>) are kept verbatim; a directive that
	// looks like one of the above inside a block must not be touched,
	// so the dropping runs on the directive lines outside blocks only.
	inlineBlockRe = regexp.MustCompile(`(?s)<([a-z-]+)>.*?</[a-z-]+>`)
	// protoRe is the vendor's `proto udp` line, replaced in warp mode.
	protoRe = regexp.MustCompile(`(?m)^[ \t]*proto\b.*\n?`)
)

// warpTCPPort is the TCP port IPVanish's OpenVPN servers listen on.
const warpTCPPort = 443

// remoteRe finds the vendor's `remote <host> [port] [proto]` line.
var remoteRe = regexp.MustCompile(`(?m)^[ \t]*remote[ \t]+([A-Za-z0-9.-]+)(?:[ \t]+(\d+))?.*\n?`)

// openVPNConfig turns a vendor .ovpn (read from the baked config dir,
// so relative file references resolve under --cd) into the config this
// provider runs: vendor transport lines kept, credential and lifecycle
// handling replaced by ours. socket is the management socket path.
// viaWarp switches the outer connection to TCP/443 through WARP's
// local SOCKS5 proxy (the vendor configs are UDP, which OpenVPN cannot
// proxy): IPVanish drops datacenter source IPs at L3, so from the
// fleet the edge is only reachable with a Cloudflare source IP.
func openVPNConfig(vendor []byte, socket string, viaWarp bool) ([]byte, error) {
	if len(socket) > 107 || strings.ContainsAny(socket, "\r\n\x00\"") {
		return nil, errors.New("invalid IPVanish management socket path")
	}
	text := strings.ReplaceAll(string(vendor), "\r\n", "\n")
	remote := remoteRe.FindStringSubmatch(text)
	if remote == nil {
		return nil, errors.New("IPVanish config has no remote")
	}
	var outer string
	if viaWarp {
		// Same server, TCP flavour, dialed through the SOCKS proxy.
		// OpenVPN resolves the hostname itself and hands the IP to
		// the proxy; a longer connect timeout covers the extra hop.
		text = remoteRe.ReplaceAllString(text, "")
		text = protoRe.ReplaceAllString(text, "")
		outer = fmt.Sprintf("proto tcp-client\nremote %s %d\nsocks-proxy %s\nconnect-timeout 25\n", remote[1], warpTCPPort, warpproxy.Addr)
	} else {
		outer = "connect-timeout 15\n"
	}
	// Protect inline blocks from the directive filter.
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
	// (typically 1370 on Talos/Cilium); with OpenVPN's default 1500
	// the TLS handshake never completes on the path.
	ours := fmt.Sprintf(`
# --- tundler ---
dev %s
dev-type tun
auth-user-pass
auth-nocache
management %s unix
management-query-passwords
management-hold
management-signal
redirect-gateway def1
pull-filter ignore "dhcp-option"
persist-key
connect-retry-max 1
%stun-mtu 1320
mssfix 1280
verb 0
`, tunnelInterface, strconv.Quote(socket), outer)
	return []byte(text + ours), nil
}

type openVPNTunnel struct {
	cmd        *exec.Cmd
	done       chan struct{}
	events     chan struct{}
	control    net.Conn
	mu         sync.RWMutex
	writeMu    sync.Mutex
	vip        string
	up         bool
	failed     bool
	authFailed bool
}

func (t *openVPNTunnel) notify() {
	select {
	case t.events <- struct{}{}:
	default:
	}
}

// address is the tunnel's virtual IP while it is up, "" otherwise.
func (t *openVPNTunnel) address() string {
	if t == nil {
		return ""
	}
	select {
	case <-t.done:
		return ""
	default:
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if !t.up || t.failed {
		return ""
	}
	return t.vip
}

func (t *openVPNTunnel) send(command string) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_ = t.control.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err := io.WriteString(t.control, command+"\n")
	return err
}

func (t *openVPNTunnel) monitor(user, pass string) {
	defer func() {
		t.mu.Lock()
		t.up = false
		t.failed = true
		t.mu.Unlock()
		t.notify()
		_ = t.control.Close()
		// Losing management supervision must also stop the owned tunnel.
		_ = t.cmd.Process.Signal(syscall.SIGTERM)
	}()
	scanner := bufio.NewScanner(t.control)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, ">HOLD:"):
			if t.send("hold release") != nil {
				return
			}
		case strings.HasPrefix(line, ">PASSWORD:Need 'Auth'"):
			if t.send("username \"Auth\" "+strconv.Quote(user)) != nil || t.send("password \"Auth\" "+strconv.Quote(pass)) != nil {
				return
			}
		case strings.HasPrefix(line, ">PASSWORD:Verification Failed"):
			t.mu.Lock()
			t.authFailed = true
			t.mu.Unlock()
			return
		case strings.HasPrefix(line, ">FATAL:"):
			return
		case strings.HasPrefix(line, ">STATE:"):
			fields := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
			var vip string
			if len(fields) >= 4 && fields[1] == "CONNECTED" && fields[2] == "SUCCESS" {
				if ip := net.ParseIP(fields[3]); ip != nil && ip.To4() != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
					vip = ip.String()
				}
			}
			t.mu.Lock()
			t.vip, t.up = vip, vip != ""
			t.mu.Unlock()
			t.notify()
		}
	}
}

// launchOpenVPN starts openvpn on config (with cd as its working
// directory so the vendor config's relative CA/key references resolve),
// drives the management handshake and waits for CONNECTED. The context
// bounds the connection attempt only, never the tunnel's lifetime.
func launchOpenVPN(ctx context.Context, cd, config, socket, user, pass string) (*openVPNTunnel, error) {
	t := &openVPNTunnel{done: make(chan struct{}), events: make(chan struct{}, 1)}
	t.cmd = exec.Command("openvpn", "--cd", cd, "--config", config)
	configureChild(t.cmd)
	t.cmd.Stdout, t.cmd.Stderr = io.Discard, io.Discard
	// The transport needs no account, vault or cloud environment.
	t.cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C"}
	if err := t.cmd.Start(); err != nil {
		return nil, errors.New("start IPVanish OpenVPN transport")
	}
	go func() { _ = t.cmd.Wait(); close(t.done); t.notify() }()
	ready := false
	defer func() {
		if !ready {
			cleanup, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			_ = t.stop(cleanup)
		}
	}()
	deadline, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for t.control == nil {
		conn, err := (&net.Dialer{}).DialContext(deadline, "unix", socket)
		if err == nil {
			t.control = conn
			break
		}
		select {
		case <-deadline.Done():
			return nil, errors.New("IPVanish OpenVPN management startup timed out")
		case <-t.done:
			return nil, errors.New("IPVanish OpenVPN exited during startup")
		case <-ticker.C:
		}
	}
	go t.monitor(user, pass)
	for _, command := range []string{"state on", "hold release"} {
		if t.send(command) != nil {
			return nil, errors.New("initialize IPVanish OpenVPN management")
		}
	}
	for {
		if t.address() != "" {
			ready = true
			return t, nil
		}
		t.mu.RLock()
		failed, authFailed := t.failed, t.authFailed
		t.mu.RUnlock()
		if authFailed {
			return nil, errAuthFailed
		}
		if failed {
			return nil, errors.New("IPVanish OpenVPN management failed before connecting")
		}
		select {
		case <-deadline.Done():
			return nil, errors.New("IPVanish OpenVPN connection timed out")
		case <-t.done:
			t.mu.RLock()
			authFailed := t.authFailed
			t.mu.RUnlock()
			if authFailed {
				return nil, errAuthFailed
			}
			return nil, errors.New("IPVanish OpenVPN exited before connecting")
		case <-t.events:
		}
	}
}

// stop terminates the owned process: SIGTERM, then SIGKILL after 5 s.
func (t *openVPNTunnel) stop(ctx context.Context) error {
	if t == nil {
		return nil
	}
	_ = t.cmd.Process.Signal(syscall.SIGTERM)
	defer func() {
		if t.control != nil {
			_ = t.control.Close()
		}
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-t.done:
		return nil
	case <-timer.C:
	case <-ctx.Done():
	}
	_ = t.cmd.Process.Kill()
	select {
	case <-t.done:
		return nil
	case <-time.After(time.Second):
		return errors.New("IPVanish OpenVPN process did not exit")
	}
}

// startTunnel writes the per-connection config into a fresh private
// run directory (removed when the process ends) and launches it.
func startTunnel(ctx context.Context, server *ipvanishServer, user, pass string) (*openVPNTunnel, error) {
	vendor, err := os.ReadFile(filepath.Join(configDir(), server.Filename))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", server.Filename, err)
	}
	if err := os.MkdirAll(runDir(), 0700); err != nil {
		return nil, errors.New("create IPVanish run directory")
	}
	dir, err := os.MkdirTemp(runDir(), "openvpn-*")
	if err != nil {
		return nil, errors.New("create IPVanish connection directory")
	}
	socket := filepath.Join(dir, "management.sock")
	config, err := openVPNConfig(vendor, socket, transport() == transportWarp)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	path := filepath.Join(dir, "client.ovpn")
	if err := os.WriteFile(path, config, 0600); err != nil {
		_ = os.RemoveAll(dir)
		return nil, errors.New("write IPVanish connection config")
	}
	tunnel, err := launchOpenVPN(ctx, configDir(), path, socket, user, pass)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	go func() { <-tunnel.done; _ = os.RemoveAll(dir) }()
	return tunnel, nil
}
