// Package ovpn runs one owned openvpn child per connection, supervised
// over a private Unix management socket. Shared by the OpenVPN-direct
// providers that need to know WHY a connect failed (ipvanish,
// protonvpn): AUTH_FAILED is classified (ErrAuthFailed) so the runtime
// can hold instead of re-logging in, a timeout or a dead server is just
// an error, and the process can never leak — it is a child of
// tundler-tunnel (a crashed supervisor takes it down, see
// configureChild), it is stopped when management supervision is lost,
// and Stop terminates exactly that child, never `pkill openvpn`.
//
// The account password travels over the management socket
// (management-query-passwords), never through a file or the
// environment. Neither OpenVPN output nor management messages are
// forwarded to logs: both can carry the credentials.
//
// The provider renders the config (it knows its vendor's directives);
// this package owns the lifecycle. A config must carry the management
// block Directives returns for the socket it is given.
package ovpn

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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ErrAuthFailed is OpenVPN's AUTH_FAILED: the server rejected the
// account's username/password. Callers report it as an auth failure
// (provider.Status.AuthFailed) rather than retrying elsewhere.
var ErrAuthFailed = errors.New("OpenVPN rejected the account credentials (AUTH_FAILED)")

// Options describe one connection attempt.
type Options struct {
	// Name labels errors ("IPVanish", "ProtonVPN").
	Name string
	// RunDir holds the per-connection private directory (config and
	// management socket); tmpfs, and short: Unix socket paths are
	// limited to 107 bytes.
	RunDir string
	// CD is openvpn's working directory, for configs with relative
	// file references ("" = none).
	CD string
	// User and Pass answer the management credential query.
	User, Pass string
	// Timeout bounds the attempt: management startup, handshake and
	// the CONNECTED state (default 35 s).
	Timeout time.Duration
}

// Directives is the management block a config must contain, with the
// socket path quoted for OpenVPN. Credentials are queried over the
// socket, held until the supervisor releases, signals delivered as
// management events.
func Directives(socket string) string {
	return "auth-user-pass\nauth-nocache\nmanagement " + strconv.Quote(socket) + " unix\nmanagement-query-passwords\nmanagement-hold\nmanagement-signal\n"
}

// ValidSocket reports whether a socket path can be used verbatim in a
// config (length and quoting).
func ValidSocket(socket string) bool {
	return len(socket) <= 107 && !strings.ContainsAny(socket, "\r\n\x00\"")
}

// Tunnel is one owned openvpn child.
type Tunnel struct {
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

func (t *Tunnel) notify() {
	select {
	case t.events <- struct{}{}:
	default:
	}
}

// Address is the tunnel's virtual IP while it is up, "" otherwise.
func (t *Tunnel) Address() string {
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

// Done is closed when the child has exited.
func (t *Tunnel) Done() <-chan struct{} {
	if t == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return t.done
}

func (t *Tunnel) send(command string) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_ = t.control.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err := io.WriteString(t.control, command+"\n")
	return err
}

func (t *Tunnel) monitor(user, pass string) {
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

// Launch starts openvpn on config, drives the management handshake over
// socket and waits for CONNECTED. The context bounds the attempt only,
// never the tunnel's lifetime.
func Launch(ctx context.Context, opts Options, config, socket string) (*Tunnel, error) {
	t := &Tunnel{done: make(chan struct{}), events: make(chan struct{}, 1)}
	args := []string{"--config", config}
	if opts.CD != "" {
		args = append([]string{"--cd", opts.CD}, args...)
	}
	t.cmd = exec.Command("openvpn", args...)
	configureChild(t.cmd)
	t.cmd.Stdout, t.cmd.Stderr = io.Discard, io.Discard
	// The transport needs no account, vault or cloud environment.
	t.cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C"}
	if err := t.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s OpenVPN transport", opts.Name)
	}
	go func() { _ = t.cmd.Wait(); close(t.done); t.notify() }()
	ready := false
	defer func() {
		if !ready {
			cleanup, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			_ = t.Stop(cleanup)
		}
	}()
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 35 * time.Second
	}
	deadline, cancel := context.WithTimeout(ctx, timeout)
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
			return nil, fmt.Errorf("%s OpenVPN management startup timed out", opts.Name)
		case <-t.done:
			return nil, fmt.Errorf("%s OpenVPN exited during startup", opts.Name)
		case <-ticker.C:
		}
	}
	go t.monitor(opts.User, opts.Pass)
	for _, command := range []string{"state on", "hold release"} {
		if t.send(command) != nil {
			return nil, fmt.Errorf("initialize %s OpenVPN management", opts.Name)
		}
	}
	for {
		if t.Address() != "" {
			ready = true
			return t, nil
		}
		t.mu.RLock()
		failed, authFailed := t.failed, t.authFailed
		t.mu.RUnlock()
		if authFailed {
			return nil, ErrAuthFailed
		}
		if failed {
			return nil, fmt.Errorf("%s OpenVPN management failed before connecting", opts.Name)
		}
		select {
		case <-deadline.Done():
			return nil, fmt.Errorf("%s OpenVPN connection timed out", opts.Name)
		case <-t.done:
			t.mu.RLock()
			authFailed := t.authFailed
			t.mu.RUnlock()
			if authFailed {
				return nil, ErrAuthFailed
			}
			return nil, fmt.Errorf("%s OpenVPN exited before connecting", opts.Name)
		case <-t.events:
		}
	}
}

// Stop terminates the owned process: SIGTERM, then SIGKILL after 5 s.
func (t *Tunnel) Stop(ctx context.Context) error {
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
		return errors.New("OpenVPN process did not exit")
	}
}

// Start renders the config for a fresh private connection directory
// (removed when the process ends) and launches it. render receives the
// management socket path the config must reference.
func Start(ctx context.Context, opts Options, render func(socket string) ([]byte, error)) (*Tunnel, error) {
	if err := os.MkdirAll(opts.RunDir, 0700); err != nil {
		return nil, fmt.Errorf("create %s run directory", opts.Name)
	}
	dir, err := os.MkdirTemp(opts.RunDir, "openvpn-*")
	if err != nil {
		return nil, fmt.Errorf("create %s connection directory", opts.Name)
	}
	socket := filepath.Join(dir, "management.sock")
	if !ValidSocket(socket) {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("%s run directory path too long for a management socket", opts.Name)
	}
	config, err := render(socket)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	path := filepath.Join(dir, "client.ovpn")
	if err := os.WriteFile(path, config, 0600); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("write %s connection config", opts.Name)
	}
	tunnel, err := Launch(ctx, opts, path, socket)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	go func() { <-tunnel.done; _ = os.RemoveAll(dir) }()
	return tunnel, nil
}

// NewForTest wraps an already started command as a Tunnel (tests of
// Stop semantics in dependent packages).
func NewForTest(cmd *exec.Cmd) *Tunnel {
	t := &Tunnel{cmd: cmd, done: make(chan struct{}), events: make(chan struct{}, 1)}
	go func() { _ = cmd.Wait(); close(t.done) }()
	return t
}
