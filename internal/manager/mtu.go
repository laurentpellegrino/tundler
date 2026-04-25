package manager

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/laurentpellegrino/tundler/internal/shared"
)

// WireGuard / IPsec UDP-encap per-packet overhead. 80 covers IPv4 outer
// transport (20 IP + 8 UDP + 32 WG header/nonce + 16 Poly1305 tag, rounded
// up for VLAN tagging headroom — same constant wg-quick uses). 96 covers
// IPv6 outer transport (the IP header grows by 20 bytes).
const (
	wgOverheadIPv4 = 80
	wgOverheadIPv6 = 96
)

// clampTunnelMTUIfNeeded walks the WireGuard tunnel interface(s) inside
// vpnns and lowers their MTU when the provider has set it too high to
// fit inside the pod's outer interface (typically eth0).
//
// Why this exists: nordvpn's CLI hardcodes nordlynx MTU=1420 (correct for
// a 1500-byte underlay) and Surfshark/ProtonVPN/Mullvad's wg-quick reads
// the underlay MTU from the default route inside vpnns — which goes
// through the veth pair (1500), not the pod's actual eth0 (1450 under
// Calico IP-in-IP, 1450 under Cilium VXLAN, etc.). On a 1450-byte
// underlay, a 1420-byte WG payload + 80 bytes of encap = 1500 bytes,
// overflowing the underlay by 50 and silently black-holing every
// full-size packet (DF set, ICMP-too-big filtered along the path).
//
// Scoped to WireGuard interfaces specifically. OpenVPN/Lightway
// providers (PIA, ExpressVPN, Surfshark/Proton in OpenVPN mode) probe
// the underlay correctly from the parent netns and pick an MTU
// appropriate for their much smaller per-packet overhead — clamping
// them to underlay-80 would needlessly drop ~70 bytes of payload per
// packet. Detection uses `wg show <iface>`: kernel WireGuard interfaces
// (including NordLynx, which is the same kernel module) respond;
// non-WG tunnels return an error and are skipped.
//
// Idempotent: if the WG tunnel MTU already fits, nothing changes.
func clampTunnelMTUIfNeeded(ctx context.Context) {
	for _, iface := range listTunnelInterfaces(ctx) {
		if !isWireGuardInterface(ctx, iface.name) {
			continue
		}
		// Per-interface: read the configured WG peer endpoint. The
		// endpoint family decides the overhead (80 vs 96), and the
		// endpoint IP is the input to `ip route get`, which picks the
		// correct outbound interface on multi-NIC hosts and folds in
		// any kernel-cached PMTU discovery for that path. Falls back
		// to eth0 when no endpoint is configured yet.
		endpointIP, endpointIsV6 := wgEndpoint(ctx, iface.name)
		underlay := readPathMTU(ctx, endpointIP)
		if underlay == 0 {
			shared.Debugf("[mtu] %s: cannot resolve underlay mtu, skipping",
				iface.name)
			continue
		}
		overhead := wgOverheadIPv4
		if endpointIsV6 {
			overhead = wgOverheadIPv6
		}
		target := underlay - overhead
		if target <= 0 {
			shared.Debugf("[mtu] %s: underlay %d - overhead %d <= 0, skipping",
				iface.name, underlay, overhead)
			continue
		}
		if iface.mtu <= target {
			continue
		}
		shared.Debugf("[mtu] %s mtu %d > underlay(%d) - overhead(%d) = %d, clamping",
			iface.name, iface.mtu, underlay, overhead, target)
		if _, err := shared.RunCmd(ctx, "ip", "link", "set", iface.name,
			"mtu", strconv.Itoa(target)); err != nil {
			shared.Debugf("[mtu] failed to clamp %s: %v", iface.name, err)
		}
	}
}

// isWireGuardInterface reports whether the named interface in vpnns is
// a kernel WireGuard device. NordLynx is the same kernel module as
// upstream WireGuard so it responds to `wg show` too; OpenVPN tun0,
// Lightway, and other non-WG tunnels return an error.
//
// A name-based fallback (`wg*` / `nordlynx`) catches the rare case
// where a provider daemon restricts WG genetlink access from other
// processes — `ip link set` only needs rtnetlink access, which is
// usually still permitted, so the clamp can still apply. False
// positives are unlikely: no non-WG tunnel ever uses these names
// in tundler's provider set.
func isWireGuardInterface(ctx context.Context, name string) bool {
	if _, err := shared.RunCmd(ctx, "wg", "show", name); err == nil {
		return true
	}
	return name == "nordlynx" || strings.HasPrefix(name, "wg")
}

// wgEndpoint returns the configured peer endpoint of a WireGuard
// interface as (ip, isIPv6). Both outputs are needed by the caller:
// the IP feeds into `ip route get` for the path-MTU lookup, and the
// family decides between the 80-byte (IPv4) and 96-byte (IPv6) WG
// overhead. Returns ("", false) when no endpoint is configured yet
// or the call fails — caller falls back to eth0 + IPv4 defaults.
//
// `wg show <iface> endpoints` output: tab-separated lines, one per
// peer, "<peer-pubkey>\t<endpoint>". IPv6 endpoints render as
// "[2001:db8::1]:51820" (bracketed); IPv4 as "1.2.3.4:51820".
func wgEndpoint(ctx context.Context, iface string) (ip string, isIPv6 bool) {
	out, err := shared.RunCmd(ctx, "wg", "show", iface, "endpoints")
	if err != nil || out == "" {
		return "", false
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		ep := strings.TrimSpace(fields[1])
		if ep == "" || ep == "(none)" {
			continue
		}
		if strings.HasPrefix(ep, "[") {
			// "[2001:db8::1]:51820" -> "2001:db8::1"
			if i := strings.Index(ep, "]"); i > 1 {
				return ep[1:i], true
			}
			continue
		}
		// "1.2.3.4:51820" -> "1.2.3.4"
		if i := strings.LastIndexByte(ep, ':'); i > 0 {
			return ep[:i], false
		}
	}
	return "", false
}

var mtuRegex = regexp.MustCompile(`mtu (\d+)`)

func parseMTU(line string) int {
	m := mtuRegex.FindStringSubmatch(line)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// readPathMTU resolves the outbound path's MTU for traffic destined to
// the given endpoint, executed in the parent netns (where the WG outer
// transport actually flows — vpnns only has the inner side).
//
// Strategy, most-specific to least-specific:
//  1. `ip route get <endpoint>` — picks the correct outbound interface
//     on multi-NIC hosts and includes any kernel-cached PMTU discovery.
//     Reports either an explicit "mtu N" token (PMTU cache hit), or a
//     "dev <name>" token (whose link MTU we then read).
//  2. `ip -o link show eth0` — fallback when no endpoint is configured
//     yet, which is the common case in containerized deployments.
//
// Returns 0 when nothing can be resolved; callers must treat that as
// "skip the clamp", not "underlay is 0".
func readPathMTU(ctx context.Context, endpointIP string) int {
	if endpointIP != "" {
		out, err := shared.RunCmdDirect(ctx, "ip", "route", "get", endpointIP)
		if err == nil {
			if mtu := parseMTU(out); mtu > 0 {
				return mtu
			}
			if dev := parseRouteDev(out); dev != "" {
				if linkOut, err := shared.RunCmdDirect(ctx,
					"ip", "-o", "link", "show", dev); err == nil {
					if mtu := parseMTU(linkOut); mtu > 0 {
						return mtu
					}
				}
			}
		}
	}
	out, err := shared.RunCmdDirect(ctx, "ip", "-o", "link", "show", "eth0")
	if err != nil {
		return 0
	}
	return parseMTU(out)
}

var routeDevRegex = regexp.MustCompile(`\bdev\s+(\S+)`)

func parseRouteDev(out string) string {
	m := routeDevRegex.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return m[1]
}

type tunnelIface struct {
	name string
	mtu  int
}

// listTunnelInterfaces enumerates POINTOPOINT-flagged interfaces inside
// vpnns. That captures every VPN tunnel device — tun0 (OpenVPN/Lightway),
// nordlynx (NordVPN), wg0 (Surfshark/Proton WireGuard), wg-mullvad
// (Mullvad) — without us needing to maintain a per-provider list.
// Loopback and veth interfaces don't carry POINTOPOINT, so they're
// excluded automatically.
func listTunnelInterfaces(ctx context.Context) []tunnelIface {
	out, err := shared.RunCmd(ctx, "ip", "-o", "link")
	if err != nil {
		return nil
	}
	var result []tunnelIface
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "POINTOPOINT") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
		mtu := parseMTU(line)
		if mtu == 0 {
			continue
		}
		result = append(result, tunnelIface{name: name, mtu: mtu})
	}
	return result
}
