// Package proxy — browser-TLS impersonation for the tunnel egress.
//
// Why this exists: some upstream edges fingerprint the TLS ClientHello
// (JA3/JA4) and blocklist non-browser signatures with 4xx regardless of exit
// IP or User-Agent. A default HTTP-client TLS stack cannot reproduce a real
// browser's ClientHello (no GREASE, wrong extension order, missing
// browser-specific extensions), and cipher-reordering tricks only produce
// NOVEL fingerprints that such edges flag just as readily.
//
// The durable approach is to originate the upstream TLS HERE, in the tunnel
// pod, with uTLS presets that replay a real Chrome/Firefox/Safari/Edge
// ClientHello byte-for-byte — statistically indistinguishable from the many
// real browser users an edge must keep serving. We rotate across several real
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
// browser's ClientHello. All are fingerprints an edge serves for genuine
// users, so blocklisting any one is collateral damage — and spreading across
// them means no single signature covers the fleet. Ordered deterministically;
// selection is by a stable key (see PickProfile), never random, so a slot
// keeps its identity across reconnects.
//
// Keep these at the NEWEST presets the pinned uTLS release ships: a browser
// version that real users stopped running long ago, arriving at crawl volume,
// is itself a signal. Refresh with every uTLS bump (2026-10-24: Edge_106 was
// dropped for a second, newer Chrome preset — uTLS has no fresher Edge).
var browserProfiles = []utls.ClientHelloID{
	utls.HelloChrome_133,
	utls.HelloChrome_131,
	utls.HelloFirefox_120,
	utls.HelloSafari_16_0,
}

// profileUserAgents pairs each preset with the User-Agent the same browser
// sends, so a client that asks for it (see UserAgentHintHeader) presents a
// consistent identity: a Chrome ClientHello under a Bingbot or Firefox UA is
// exactly the kind of contradiction bot scoring keys on. Keyed by the
// preset's Str() so a preset missing here fails loudly in tests.
var profileUserAgents = map[string]string{
	utls.HelloChrome_133.Str():  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	utls.HelloChrome_131.Str():  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	utls.HelloFirefox_120.Str(): "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	utls.HelloSafari_16_0.Str(): "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
}

// UserAgentFor returns the User-Agent string that matches a preset's browser,
// or "" for a preset outside the rotation set.
func UserAgentFor(hello utls.ClientHelloID) string {
	return profileUserAgents[hello.Str()]
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
// the given browser's ClientHello using cfg (which must at least set
// ServerName for SNI + cert verification). The returned *utls.UConn is a
// net.Conn carrying application data; ALPN is whatever the preset offers
// (browsers offer h2,http/1.1) so the caller can honour the negotiated
// protocol. The caller owns closing it.
func HandshakeAs(ctx context.Context, raw net.Conn, cfg *utls.Config, hello utls.ClientHelloID) (*utls.UConn, error) {
	uconn := utls.UClient(raw, cfg, hello)
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = uconn.Close()
		return nil, err
	}
	return uconn, nil
}
