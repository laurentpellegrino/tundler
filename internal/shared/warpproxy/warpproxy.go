// Package warpproxy drives Cloudflare WARP in *proxy mode* as an outer
// transport for providers whose edges drop datacenter source IPs
// (FastVPN and IPVanish, both on the StrongTechnology/WLVPN backbone).
//
// Proxy mode (`warp-cli mode proxy`) is a local SOCKS5 proxy on
// 127.0.0.1:40000 and nothing else: no CloudflareWARP device, no policy
// routing, no nftables kill switch, no resolv.conf rewrite. OpenVPN
// dials its TCP edge through it (`socks-proxy`; OpenVPN's SOCKS support
// is TCP-only) and presents a Cloudflare source IP the edge accepts.
// The only routing rule is PinEdge: Cloudflare's WARP block stays on
// the original gateway so openvpn's redirect-gateway never swallows
// WARP's own MASQUE/DoH packets (that circular dependency stalls
// WARP's reconnect).
//
// History (fastvpn, 2026-05/10): tunnel mode — WARP as the system
// default route with openvpn nested inside — worked only after punching
// accept rules into WARP's policy-drop nftables chains, pinning DoH
// resolvers on its device and disabling IPv6 on it, and warp-svc
// rebuilds that table on every interface change, i.e. every rotation.
// Proxy mode needs none of it.
package warpproxy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	cli = "warp-cli"
	// Port is where warp-svc listens in proxy mode (its default).
	Port = "40000"
	// Addr is the SOCKS5 proxy address for an OpenVPN `socks-proxy` line.
	Addr = "127.0.0.1 " + Port
	// EdgeRange is Cloudflare's WARP anycast block: the MASQUE endpoints
	// (162.159.198.x) and the DoH resolvers (162.159.36.1, 162.159.46.1).
	EdgeRange = "162.159.0.0/16"
	trace     = "https://www.cloudflare.com/cdn-cgi/trace"
)

var flags = []string{"--accept-tos"}

func run(ctx context.Context, args ...string) (string, error) {
	return shared.RunCmd(ctx, cli, append(append([]string(nil), flags...), args...)...)
}

// On probes Cloudflare's trace endpoint THROUGH the SOCKS proxy — the
// authoritative "proxy is actually forwarding" signal (warp-cli status
// flips to Connected a moment before traffic flows, and a direct probe
// would only describe the host's own path).
func On(ctx context.Context) bool {
	out, err := shared.RunCmd(ctx, "curl", "-s", "--max-time", "5",
		"--socks5-hostname", "127.0.0.1:"+Port, trace)
	if err != nil {
		return false
	}
	for _, ln := range strings.Split(out, "\n") {
		if strings.TrimSpace(ln) == "warp=on" {
			return true
		}
	}
	return false
}

// Up ensures the WARP SOCKS proxy is forwarding. Idempotent: registers
// only when no live registration exists, switches to proxy mode,
// connects and polls until the proxy forwards. The registration is
// never deleted on rotation — WARP is pure transport, not the rotating
// exit identity (the VPN provider is).
func Up(ctx context.Context) error {
	if On(ctx) {
		return nil
	}
	reg, _ := run(ctx, "registration", "show")
	low := strings.ToLower(reg)
	if !strings.Contains(low, "device id") && !strings.Contains(low, "account") {
		if _, err := run(ctx, "registration", "new"); err != nil {
			return fmt.Errorf("warp registration new: %w", err)
		}
	}
	if _, err := run(ctx, "mode", "proxy"); err != nil {
		return fmt.Errorf("warp mode proxy: %w", err)
	}
	_, _ = run(ctx, "proxy", "port", Port)
	if _, err := run(ctx, "connect"); err != nil {
		return fmt.Errorf("warp connect: %w", err)
	}
	for i := 0; i < 60; i++ {
		if On(ctx) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("warp proxy did not reach warp=on within 30s")
}

// origDefaultGateway returns the eth0 next-hop from the main table's
// default route. openvpn's `redirect-gateway def1` adds 0.0.0.0/1 and
// 128.0.0.0/1 on top of it rather than replacing it, so this stays
// "via <gw> dev eth0" with the tunnel up.
func origDefaultGateway(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, "ip", "route", "show", "default", "dev", "eth0")
	if err != nil || strings.TrimSpace(out) == "" {
		// Fall back to the unscoped default.
		out, err = shared.RunCmd(ctx, "ip", "route", "show", "default")
		if err != nil {
			return "", err
		}
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no `via` gateway in default route: %q", out)
}

// PinEdge routes Cloudflare's WARP block via the original gateway. /16
// is more specific than openvpn's 0.0.0.0/1 and 128.0.0.0/1, so the
// order relative to openvpn's start doesn't matter. Idempotent.
func PinEdge(ctx context.Context) error {
	gw, err := origDefaultGateway(ctx)
	if err != nil {
		return fmt.Errorf("find original gateway: %w", err)
	}
	if _, err := shared.RunCmd(ctx, "ip", "route", "replace", EdgeRange, "via", gw, "dev", "eth0"); err != nil {
		return fmt.Errorf("pin warp edge %s: %w", EdgeRange, err)
	}
	return nil
}
