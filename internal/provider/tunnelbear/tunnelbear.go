// Package tunnelbear drives TunnelBear as a proxy-chain provider.
//
// Unlike every other tundler provider (OpenVPN, WireGuard, vendor CLIs)
// TunnelBear is NOT a kernel tunnel: its "VPN" is an authenticated HTTPS
// CONNECT proxy on each lazerpenguin.com edge (port 8080). Instead of
// bringing up tun0 and letting the pod's default route carry traffic,
// this provider installs a custom dialer on the in-process CONNECT proxy
// (proxy.Server.SetDialer): every crawler CONNECT is tunneled through the
// chosen TunnelBear edge, authorized with the account's vpn_token. The
// exit IP is the edge server's own IP.
//
// Auth (see client.go) is a single account username/password
// (TUNNELBEAR_USERNAME / TUNNELBEAR_PASSWORD from OpenBao vpn/tunnelbear)
// on a paid Unlimited plan (no data cap). The vpn_token is account-wide,
// so all pods share one credential; per-pod distinct exit IPs come from
// each pod selecting a different edge.
package tunnelbear

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/proxy"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const name = "tunnelbear"

// sessionTTL bounds how long a PolarBear bearer + vpn_token are reused
// before a fresh login. Rotations are minutes-to-hours apart, so this
// keeps dashboard logins (the anti-abuse-sensitive step) infrequent
// while staying well inside the token's server-side lifetime.
const sessionTTL = 25 * time.Minute

// proxyDialTimeout bounds a single upstream CONNECT-through-TunnelBear
// (TCP + TLS + CONNECT round-trip). The proxy core wraps the dial in
// its own upstreamDialTimeout too; this is the inner ceiling.
const proxyDialTimeout = 12 * time.Second

// TunnelBear's supported countries (ISO codes), used as the location
// set. Mirrors the official client's country list; each maps to a
// /vpns/countries/<cc> lookup at Connect time.
var countries = []string{
	"ar", "au", "at", "be", "br", "bg", "ca", "cl", "co", "cy", "cz", "dk",
	"fi", "fr", "de", "gr", "hu", "id", "ie", "it", "jp", "ke", "kr", "lv",
	"lt", "my", "mx", "md", "nl", "nz", "ng", "no", "pe", "ph", "pl", "pt",
	"ro", "rs", "sg", "si", "za", "es", "se", "ch", "tw", "ae", "gb", "us",
}

type TunnelBear struct{}

func init() { provider.Registry[name] = TunnelBear{} }

// ---- package state ----------------------------------------------------

var (
	srv *proxy.Server // the in-process CONNECT proxy; set via AttachProxy

	mu        sync.Mutex
	pbToken   string
	vpnToken  string
	sessionAt time.Time // when pbToken/vpnToken were minted
	loggedIn  bool

	activeServer   *vpnServer
	activeLocation string
)

// AttachProxy wires the provider to the pod's CONNECT proxy and fails
// closed until the first Connect: with no edge selected yet, dialing
// must error rather than fall back to a direct (leaking) dial. main()
// calls this once at startup via a type assertion.
func (TunnelBear) AttachProxy(s *proxy.Server) {
	srv = s
	s.SetDialer(disconnectedDialer)
}

func disconnectedDialer(context.Context, string) (net.Conn, error) {
	return nil, fmt.Errorf("tunnelbear: no edge selected (not connected)")
}

func getCredentials() (string, string, error) {
	user := os.Getenv("TUNNELBEAR_USERNAME")
	pass := os.Getenv("TUNNELBEAR_PASSWORD")
	if user == "" || pass == "" {
		return "", "", fmt.Errorf("TUNNELBEAR_USERNAME and TUNNELBEAR_PASSWORD environment variables must be set")
	}
	return user, pass, nil
}

// ensureSession returns a valid (pbToken, vpnToken), refreshing via a
// full login when the cached pair is missing or older than sessionTTL.
// force bypasses the cache (used after an auth failure mid-flight).
func ensureSession(ctx context.Context, force bool) (string, string, error) {
	mu.Lock()
	if !force && vpnToken != "" && time.Since(sessionAt) < sessionTTL {
		pb, vt := pbToken, vpnToken
		mu.Unlock()
		return pb, vt, nil
	}
	mu.Unlock()

	user, pass, err := getCredentials()
	if err != nil {
		return "", "", err
	}
	c := newAPIClient()
	if err := c.getCSRF(ctx); err != nil {
		return "", "", err
	}
	access, err := c.dashboardToken(ctx, user, pass)
	if err != nil {
		return "", "", err
	}
	pb, err := c.exchangePB(ctx, access)
	if err != nil {
		return "", "", err
	}
	ui, err := c.getUser(ctx, pb)
	if err != nil {
		return "", "", err
	}
	if ui.VpnToken == "" {
		return "", "", fmt.Errorf("tunnelbear: account has no vpn_token (status=%s tier=%d)", ui.AccountStatus, ui.Tier)
	}

	mu.Lock()
	pbToken, vpnToken, sessionAt = pb, ui.VpnToken, time.Now()
	mu.Unlock()
	return pb, ui.VpnToken, nil
}

// ---- VPNProvider ------------------------------------------------------

func (TunnelBear) Login(ctx context.Context) error {
	_, _, err := ensureSession(ctx, true)
	mu.Lock()
	loggedIn = err == nil
	mu.Unlock()
	return err
}

func (TunnelBear) Logout(context.Context) error {
	mu.Lock()
	pbToken, vpnToken, loggedIn = "", "", false
	activeServer, activeLocation = nil, ""
	mu.Unlock()
	if srv != nil {
		srv.SetDialer(disconnectedDialer)
	}
	return nil
}

func (TunnelBear) LoggedIn(context.Context) bool {
	mu.Lock()
	defer mu.Unlock()
	return loggedIn
}

func (TunnelBear) Locations(context.Context) []string {
	out := make([]string, len(countries))
	copy(out, countries)
	return out
}

// Connect selects an edge in the requested country and points the
// in-process proxy's dialer at it. An empty location picks a random
// country. Returns immediately with the edge IP as the exit IP — the
// caller's exit-IP contract test (which dials through this very proxy)
// confirms the traffic actually egresses there.
func (t TunnelBear) Connect(ctx context.Context, location string) provider.Status {
	if srv == nil {
		return provider.Status{Connected: false, Provider: name}
	}
	cc := strings.ToLower(strings.TrimSpace(location))
	if cc == "" {
		cc = countries[rand.Intn(len(countries))]
	}

	pb, vt, err := ensureSession(ctx, false)
	if err != nil {
		shared.Debugf("[tunnelbear] connect: session: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: cc}
	}

	c := newAPIClient()
	vr, err := c.getServers(ctx, pb, cc)
	if err != nil {
		// Token may have lapsed — one forced re-login, then retry.
		if pb, vt, err = ensureSession(ctx, true); err == nil {
			vr, err = c.getServers(ctx, pb, cc)
		}
		if err != nil {
			shared.Debugf("[tunnelbear] connect: getServers: %v", err)
			return provider.Status{Connected: false, Provider: name, Location: cc}
		}
	}
	if len(vr.Vpns) == 0 {
		shared.Debugf("[tunnelbear] connect: no edges for %q", cc)
		return provider.Status{Connected: false, Provider: name, Location: cc}
	}

	edge := vr.Vpns[rand.Intn(len(vr.Vpns))]
	proxyHost := edge.URL // cert-matching hostname (resolves to edge.Host)
	if proxyHost == "" {
		proxyHost = edge.Host
	}
	dialer := makeEdgeDialer(proxyHost, vt)
	srv.SetDialer(dialer)
	srv.SetExitIP(edge.Host)

	mu.Lock()
	e := edge
	activeServer = &e
	activeLocation = cc
	mu.Unlock()

	region := vr.RegionName
	if region == "" {
		region = strings.ToUpper(cc)
	}
	shared.Debugf("[tunnelbear] connected via %s (%s) exit=%s", proxyHost, region, edge.Host)
	return provider.Status{Connected: true, Provider: name, IP: edge.Host, Location: cc, Region: region}
}

func (TunnelBear) Disconnect(context.Context) error {
	mu.Lock()
	activeServer, activeLocation = nil, ""
	mu.Unlock()
	if srv != nil {
		srv.SetDialer(disconnectedDialer) // fail closed; no direct-dial leak
	}
	return nil
}

func (TunnelBear) Connected(context.Context) bool {
	mu.Lock()
	defer mu.Unlock()
	return activeServer != nil
}

func (t TunnelBear) Status(context.Context) provider.Status {
	mu.Lock()
	defer mu.Unlock()
	if activeServer == nil {
		return provider.Status{Connected: false, Provider: name}
	}
	return provider.Status{
		Connected: true,
		Provider:  name,
		IP:        activeServer.Host,
		Location:  activeLocation,
		Region:    strings.ToUpper(activeLocation),
	}
}

func (TunnelBear) ActiveLocation(context.Context) string {
	mu.Lock()
	defer mu.Unlock()
	return activeLocation
}

func (TunnelBear) Version(context.Context) (string, error) {
	return "tunnelbear-proxy (polarbear)", nil
}

// ---- upstream dialer --------------------------------------------------

// makeEdgeDialer returns a DialFunc that tunnels a target through the
// given TunnelBear edge: TCP → TLS (SNI = proxyHost) → CONNECT target
// with Proxy-Authorization: Basic base64(token:token) → splice. The
// vpn_token is used as BOTH username and password (matching the
// official extension's onAuthRequired handler).
func makeEdgeDialer(proxyHost, token string) proxy.DialFunc {
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(token+":"+token))
	proxyAddr := net.JoinHostPort(proxyHost, proxyPort)

	return func(ctx context.Context, target string) (net.Conn, error) {
		dctx, cancel := context.WithTimeout(ctx, proxyDialTimeout)
		defer cancel()

		var d net.Dialer
		raw, err := d.DialContext(dctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("tunnelbear edge dial %s: %w", proxyAddr, err)
		}
		tconn := tls.Client(raw, &tls.Config{ServerName: proxyHost})
		if err := tconn.HandshakeContext(dctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("tunnelbear edge TLS %s: %w", proxyHost, err)
		}
		if dl, ok := dctx.Deadline(); ok {
			_ = tconn.SetDeadline(dl)
		}

		req := "CONNECT " + target + " HTTP/1.1\r\n" +
			"Host: " + target + "\r\n" +
			"Proxy-Authorization: " + authHeader + "\r\n" +
			"Proxy-Connection: keep-alive\r\n\r\n"
		if _, err := tconn.Write([]byte(req)); err != nil {
			tconn.Close()
			return nil, fmt.Errorf("tunnelbear edge CONNECT write: %w", err)
		}

		br := bufio.NewReader(tconn)
		status, err := br.ReadString('\n')
		if err != nil {
			tconn.Close()
			return nil, fmt.Errorf("tunnelbear edge CONNECT response: %w", err)
		}
		if !strings.Contains(status, " 200 ") {
			tconn.Close()
			return nil, fmt.Errorf("tunnelbear edge CONNECT %s: %s", target, strings.TrimSpace(status))
		}
		// Consume the rest of the response headers up to the blank line.
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				tconn.Close()
				return nil, fmt.Errorf("tunnelbear edge CONNECT headers: %w", err)
			}
			if strings.TrimSpace(line) == "" {
				break
			}
		}
		_ = tconn.SetDeadline(time.Time{}) // clear; proxy sets the tunnel deadline

		// Preserve any bytes buffered past the headers (none expected for
		// CONNECT, but correctness over assumption).
		return &bufferedConn{Conn: tconn, r: br}, nil
	}
}

// bufferedConn lets the spliced tunnel read through the bufio.Reader
// used to parse the CONNECT response, so no buffered tunnel bytes are
// dropped. Writes/Close/deadlines pass straight to the TLS conn.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }
