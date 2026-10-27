package ipvanish

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/laurentpellegrino/tundler/internal/shared/ovpn"
	"github.com/laurentpellegrino/tundler/internal/shared/warpproxy"
)

// The openvpn child is owned and supervised by internal/shared/ovpn:
// password over the management socket, AUTH_FAILED classified, no
// process leaks. This file renders the per-connection config from the
// vendor's baked .ovpn.

// tunnelInterface is the fixed tun name the tunnel comes up on, so the
// connected check never confuses a stale interface from a previous
// attempt with the live one (15 characters is the kernel limit).
const tunnelInterface = "tun-ipvanish"

// warpTCPPort is the TCP port IPVanish's OpenVPN servers listen on.
const warpTCPPort = 443

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
	// remoteRe finds the vendor's `remote <host> [port] [proto]` line.
	remoteRe = regexp.MustCompile(`(?m)^[ \t]*remote[ \t]+([A-Za-z0-9.-]+)(?:[ \t]+(\d+))?.*\n?`)
)

// openVPNConfig turns a vendor .ovpn (read from the baked config dir,
// so relative file references resolve under --cd) into the config this
// provider runs: vendor transport lines kept, credential and lifecycle
// handling replaced by ours. socket is the management socket path.
// viaWarp switches the outer connection to TCP/443 through WARP's
// local SOCKS5 proxy (the vendor configs are UDP, which OpenVPN cannot
// proxy): IPVanish drops datacenter source IPs at L3, so from the
// fleet the edge is only reachable with a Cloudflare source IP.
func openVPNConfig(vendor []byte, socket string, viaWarp bool) ([]byte, error) {
	if !ovpn.ValidSocket(socket) {
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
	ours := "\n# --- tundler ---\ndev " + tunnelInterface + "\ndev-type tun\n" + ovpn.Directives(socket) +
		"redirect-gateway def1\npull-filter ignore \"dhcp-option\"\npersist-key\nconnect-retry-max 1\n" + outer +
		"tun-mtu 1320\nmssfix 1280\nverb 0\n"
	return []byte(text + ours), nil
}

// startTunnel launches an owned openvpn for server.
func startTunnel(ctx context.Context, server *ipvanishServer, user, pass string) (*ovpn.Tunnel, error) {
	vendor, err := os.ReadFile(filepath.Join(configDir(), server.Filename))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", server.Filename, err)
	}
	viaWarp := transport() == transportWarp
	return ovpn.Start(ctx, ovpn.Options{Name: "IPVanish", RunDir: runDir(), CD: configDir(), User: user, Pass: pass, Timeout: connectTimeout},
		func(socket string) ([]byte, error) { return openVPNConfig(vendor, socket, viaWarp) })
}
