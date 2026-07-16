// Package proxy — browser-TLS impersonation for the crawl egress.
//
// Why this exists: ipinfo.io sits behind Cloudflare, which JA3/JA4-
// fingerprints the TLS ClientHello and blocklists non-browser signatures
// with 403/406 regardless of exit IP or User-Agent. The crawler's JVM/Netty
// TLS stack cannot reproduce a real browser's ClientHello (no GREASE, wrong
// extension order, no browser-specific extensions), and cipher-reordering
// tricks only produce NOVEL fingerprints that Cloudflare flags just as
// readily (proven 2026-07-16: reordered JDK ciphers still drew 406s).
//
// The durable fix is to do the upstream TLS HERE, in the tunnel pod, with
// uTLS presets that replay a real Chrome/Firefox/Safari/Edge ClientHello
// byte-for-byte — statistically indistinguishable from the millions of real
// browser users Cloudflare must keep serving. We rotate across several real
// presets so no single fingerprint carries the whole fleet.
package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"

	utls "github.com/refraction-networking/utls"
)

// browserProfiles is the rotation set: each entry replays a real, high-volume
// browser's ClientHello. All are fingerprints Cloudflare serves for genuine
// users, so blocklisting any one is collateral damage they won't take — and
// spreading across them means no single signature covers the fleet. Ordered
// deterministically; selection is by a stable key (see PickProfile), never
// Math.random/rand so a slot keeps its identity across reconnects.
var browserProfiles = []utls.ClientHelloID{
	utls.HelloChrome_120,
	utls.HelloFirefox_120,
	utls.HelloSafari_16_0,
	utls.HelloEdge_106,
}

// ProfileCount is the number of distinct browser fingerprints in rotation.
func ProfileCount() int { return len(browserProfiles) }

// PickProfile deterministically maps a stable key (e.g. the tunnel pod name)
// to one browser profile, so a given tunnel always presents the same real
// browser — stable identity, spread across the fleet. Uses SHA-256 rather
// than string hashCode so the distribution is even and platform-independent.
func PickProfile(key string) utls.ClientHelloID {
	sum := sha256.Sum256([]byte(key))
	idx := binary.BigEndian.Uint64(sum[:8]) % uint64(len(browserProfiles))
	return browserProfiles[idx]
}

// HandshakeAs performs a uTLS handshake over an already-dialed connection
// (raw is typically the VPN-routed conn from the proxy's DialFunc), presenting
// the given browser's ClientHello with serverName as SNI. The returned
// *utls.UConn is a net.Conn carrying application data; ALPN is whatever the
// preset offers (browsers offer h2,http/1.1) so the caller can honour the
// negotiated protocol. The caller owns closing it.
func HandshakeAs(ctx context.Context, raw net.Conn, serverName string, hello utls.ClientHelloID) (*utls.UConn, error) {
	uconn := utls.UClient(raw, &utls.Config{ServerName: serverName}, hello)
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = uconn.Close()
		return nil, err
	}
	return uconn, nil
}
