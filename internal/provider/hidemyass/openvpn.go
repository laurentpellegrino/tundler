package hidemyass

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const tunnelInterface = "tundler-hma"

var errTransportAuthentication = errors.New("HMA OpenVPN device authentication failed")

// One owned child process and one private Unix management socket per connection.
// Neither OpenVPN output nor management messages may be forwarded to logs.
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

func openVPNConfig(server vpnServer, creds vpnCredentials, socket string) ([]byte, error) {
	ip := net.ParseIP(server.IP)
	if ip == nil || ip.To4() == nil || !strings.EqualFold(server.Protocol, "openvpn") {
		return nil, errors.New("invalid HMA OpenVPN endpoint")
	}
	port := 0
	for _, candidate := range server.UDPPorts {
		if candidate > 0 && candidate <= 65535 {
			port = candidate
			break
		}
	}
	if len(socket) > 107 || port == 0 || creds.DeviceUDID == "" || creds.DevicePassword == "" || strings.ContainsAny(creds.DeviceUDID+creds.DevicePassword+socket, "\r\n\x00") {
		return nil, errors.New("incomplete HMA OpenVPN configuration")
	}
	ca := []byte(creds.OpenVPNCA)
	if !strings.Contains(creds.OpenVPNCA, "-----BEGIN CERTIFICATE-----") {
		var err error
		ca, err = base64.StdEncoding.DecodeString(creds.OpenVPNCA)
		if err != nil {
			return nil, errors.New("invalid HMA OpenVPN trust bundle")
		}
	}
	// Re-encode certificates rather than interpolate vendor text into a config.
	// Only the provider's API-supplied CA bundle is trusted, never the OS CA set.
	var trusted []byte
	for len(ca) > 0 {
		block, rest := pem.Decode(ca)
		if block == nil {
			return nil, errors.New("invalid HMA OpenVPN trust bundle")
		}
		ca = bytes.TrimSpace(rest)
		cert, err := x509.ParseCertificate(block.Bytes)
		if block.Type != "CERTIFICATE" || err != nil || !cert.IsCA {
			return nil, errors.New("invalid HMA OpenVPN CA certificate")
		}
		// The API currently includes a retired, expired CA alongside the current
		// Sectigo root. Ignore retired anchors and require a usable root below.
		if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
			continue
		}
		trusted = append(trusted, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	if len(trusted) == 0 {
		return nil, errors.New("empty HMA OpenVPN trust bundle")
	}
	return []byte(fmt.Sprintf(`client
dev %s
dev-type tun
proto udp4
remote %s %d
nobind
remote-cert-tls server
verify-x509-name openvpn.gen-vpn.com name
tls-version-min 1.2
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
connect-timeout 15
verb 0
<ca>
%s</ca>
`, tunnelInterface, ip.String(), port, strconv.Quote(socket), trusted)), nil
}

func (t *openVPNTunnel) notify() {
	select {
	case t.events <- struct{}{}:
	default:
	}
}

func (t *openVPNTunnel) address() string {
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

func (t *openVPNTunnel) monitor(creds vpnCredentials) {
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
			if t.send("username \"Auth\" "+strconv.Quote(creds.DeviceUDID)) != nil || t.send("password \"Auth\" "+strconv.Quote(creds.DevicePassword)) != nil {
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

func launchOpenVPN(ctx context.Context, config, socket string, creds vpnCredentials) (*openVPNTunnel, error) {
	t := &openVPNTunnel{done: make(chan struct{}), events: make(chan struct{}, 1)}
	t.cmd = exec.Command("openvpn", "--config", config)
	configureChild(t.cmd)
	t.cmd.Stdout, t.cmd.Stderr = io.Discard, io.Discard
	// The transport needs no account, vault, or cloud environment credentials.
	t.cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C"}
	if err := t.cmd.Start(); err != nil {
		return nil, errors.New("start HMA OpenVPN transport")
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
	deadline, cancel := context.WithTimeout(ctx, 35*time.Second)
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
			return nil, errors.New("HMA OpenVPN management startup timed out")
		case <-t.done:
			return nil, errors.New("HMA OpenVPN exited during startup")
		case <-ticker.C:
		}
	}
	go t.monitor(creds)
	for _, command := range []string{"state on", "hold release"} {
		if t.send(command) != nil {
			return nil, errors.New("initialize HMA OpenVPN management")
		}
	}
	for {
		if t.address() != "" {
			ready = true
			return t, nil
		}
		t.mu.RLock()
		failed := t.failed
		authFailed := t.authFailed
		t.mu.RUnlock()
		if authFailed {
			return nil, errTransportAuthentication
		}
		if failed {
			return nil, errors.New("HMA OpenVPN authentication or management failed")
		}
		select {
		case <-deadline.Done():
			return nil, errors.New("HMA OpenVPN connection timed out")
		case <-t.done:
			t.mu.RLock()
			authFailed := t.authFailed
			t.mu.RUnlock()
			if authFailed {
				return nil, errTransportAuthentication
			}
			return nil, errors.New("HMA OpenVPN exited before connecting")
		case <-t.events:
		}
	}
}

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
		return errors.New("HMA OpenVPN process did not exit")
	}
}

func startTunnel(ctx context.Context, dir string, server vpnServer, creds vpnCredentials) (*openVPNTunnel, error) {
	// A fresh private directory prevents stale sockets or state from another child.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("create HMA transport directory")
	}
	runDir, err := os.MkdirTemp(dir, "openvpn-*")
	if err != nil {
		return nil, errors.New("create HMA connection directory")
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(runDir)
		}
	}()
	socket := filepath.Join(runDir, "management.sock")
	config, err := openVPNConfig(server, creds, socket)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(runDir, "client.ovpn")
	if err = writePrivate(path, config); err != nil {
		return nil, err
	}
	tunnel, err := launchOpenVPN(ctx, path, socket, creds)
	if err != nil {
		return nil, err
	}
	go func() { <-tunnel.done; _ = os.RemoveAll(runDir) }()
	return tunnel, nil
}

func probePublicIP(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) string {
	transport := &http.Transport{DialContext: dial}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://icanhazip.com", nil)
	if err != nil {
		return ""
	}
	response, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil {
		return ""
	}
	ip := net.ParseIP(strings.TrimSpace(string(raw)))
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.String()
}
