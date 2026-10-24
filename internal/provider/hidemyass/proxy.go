package hidemyass

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"sync"

	"github.com/laurentpellegrino/tundler/internal/proxy"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

type tunnelConn struct {
	net.Conn
	once sync.Once
}

func (c *tunnelConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); hmaState.mu.Lock(); delete(hmaState.conns, c); hmaState.mu.Unlock() })
	return err
}

// Bind every proxied socket to the negotiated IPv4 virtual address. Together
// with the per-address interface rule this prevents fallback to host egress.
func (HideMyAss) AttachProxy(server *proxy.Server) { server.SetDialer(dialTunnel) }
func dialTunnel(ctx context.Context, target string) (net.Conn, error) {
	hmaState.mu.RLock()
	active := hmaState.active
	hmaState.mu.RUnlock()
	if active == nil || active.Tunnel == nil || active.VIP != active.Tunnel.address() || net.ParseIP(active.VIP) == nil {
		return nil, errors.New("HMA tunnel is disconnected")
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(active.VIP)}}
	conn, err := dialer.DialContext(ctx, "tcp4", target)
	if err != nil {
		return nil, err
	}
	guarded := &tunnelConn{Conn: conn}
	hmaState.mu.Lock()
	if hmaState.active != active {
		hmaState.mu.Unlock()
		_ = conn.Close()
		return nil, errors.New("HMA tunnel changed while dialing")
	}
	if hmaState.conns == nil {
		hmaState.conns = map[*tunnelConn]bool{}
	}
	hmaState.conns[guarded] = true
	hmaState.mu.Unlock()
	return guarded, nil
}

func policyRule(ctx context.Context, vip string, install bool) error {
	if ip := net.ParseIP(vip); ip == nil || ip.To4() == nil {
		return errors.New("invalid HMA virtual address")
	}
	args := []string{"-s", vip + "/32", "!", "-o", tunnelInterface, "-j", "REJECT"}
	base := []string{"-w", "3"}
	check := append(append(append([]string{}, base...), "-C", "OUTPUT"), args...)
	if _, err := shared.RunCmdSilent(ctx, "iptables", check...); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			return errors.New("query HMA VPN egress protection")
		}
		if !install {
			return nil
		}
		insert := append(append(append([]string{}, base...), "-I", "OUTPUT", "1"), args...)
		if _, err := shared.RunCmdSilent(ctx, "iptables", insert...); err != nil {
			return errors.New("install HMA VPN egress protection")
		}
	} else if !install {
		remove := append(append(append([]string{}, base...), "-D", "OUTPUT"), args...)
		if _, err := shared.RunCmdSilent(ctx, "iptables", remove...); err != nil {
			return errors.New("remove HMA VPN egress protection")
		}
	}
	return nil
}
