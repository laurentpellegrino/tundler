// Package proxylist is a vendor-agnostic proxy-chain provider: the pod
// forwards every crawler CONNECT through one upstream HTTP(S) CONNECT
// proxy taken from a list the operator supplies (static ISP/residential
// proxies, a vendor gateway with sticky sessions, a self-hosted squid…).
// No VPN client, no kernel tunnel, no vendor API: the exit IP is whatever
// the upstream proxy egresses from, read back by the post-connect
// contract probe (Status.IP is left empty on purpose).
//
// Account fields (accounts model, or legacy env PROXYLIST_ENDPOINTS /
// PROXYLIST_USERNAME / PROXYLIST_PASSWORD):
//
//	endpoints  one upstream per line:  [scheme://][user:pass@]host:port[ label]
//	           scheme http (plain CONNECT, default) or https (TLS to the
//	           proxy first). Credentials in the URL override username/
//	           password. The optional label names the location; it
//	           defaults to host:port. Blank lines and # comments ignored.
//	           Start a label with a country code or name ("us-nyc-1",
//	           "germany-2") and the region-spread preference and the
//	           /status country work for it like any other provider.
//	username   default Proxy-Authorization user for endpoints without one
//	password   default Proxy-Authorization password
//
// Each endpoint is one "location": Locations() lists the labels,
// Connect(label) points the in-process proxy's dialer at that upstream,
// and a rotation is just a Connect to another label, so EXCLUDED_LOCATIONS,
// the location cooldown and the refused-exit memory all apply unchanged.
// One pod owns one account; with Slots=1 per-pod accounts every pod gets
// its own private list (static IPs), with a shared account every pod
// draws from the same pool (gateway sessions).
package proxylist

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/accounts"
	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/proxy"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	name           = "proxylist"
	fieldEndpoints = "endpoints"

	// proxyDialTimeout bounds TCP (+TLS) + CONNECT to the upstream. Same
	// budget as tunnelbear: the proxy core wraps the dial in its own
	// watchdog, this only keeps a dead upstream from pinning a worker.
	proxyDialTimeout = 15 * time.Second
)

// Endpoint is one parsed upstream proxy.
type Endpoint struct {
	Label    string // location name (operator label or host:port)
	Host     string
	Port     string
	TLS      bool   // https://: TLS to the proxy before CONNECT
	Username string // empty = anonymous
	Password string
}

// Addr is host:port.
func (e Endpoint) Addr() string { return net.JoinHostPort(e.Host, e.Port) }

type ProxyList struct{}

func init() {
	provider.Registry[name] = ProxyList{}
	accounts.RegisterLegacyShim(name, accounts.LegacyEnvFields(map[string]string{
		fieldEndpoints:         "PROXYLIST_ENDPOINTS",
		accounts.FieldUsername: "PROXYLIST_USERNAME",
		accounts.FieldPassword: "PROXYLIST_PASSWORD",
	}))
}

// ---- package state ----------------------------------------------------

var (
	srv *proxy.Server // the in-process CONNECT proxy; set via AttachProxy

	// tlsRootCAs is nil in production (system roots); tests point it at
	// their self-signed upstream.
	tlsRootCAs *x509.CertPool

	mu       sync.Mutex
	pool     []Endpoint // parsed at Login
	loggedIn bool
	active   *Endpoint
)

// AttachProxy wires the provider to the pod's CONNECT proxy and fails
// closed until the first Connect (no direct-dial leak before an upstream
// is chosen). main() calls this once at startup via a type assertion.
func (ProxyList) AttachProxy(s *proxy.Server) {
	srv = s
	s.SetDialer(disconnectedDialer)
}

func disconnectedDialer(context.Context, string) (net.Conn, error) {
	return nil, errors.New("proxylist: no upstream selected (not connected)")
}

// ---- parsing ----------------------------------------------------------

// ParseEndpoints parses the endpoints field. Every non-blank, non-comment
// line must yield a usable host:port or the whole list is rejected: a
// typo must surface as an auth failure on /status, not as a silently
// smaller pool.
func ParseEndpoints(text, defaultUser, defaultPass string) ([]Endpoint, error) {
	var out []Endpoint
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		spec, label, _ := strings.Cut(line, " ")
		label = strings.TrimSpace(label)
		if !strings.Contains(spec, "://") {
			spec = "http://" + spec
		}
		u, err := url.Parse(spec)
		if err != nil {
			return nil, fmt.Errorf("proxylist: endpoints line %d: %w", n, err)
		}
		e := Endpoint{Host: u.Hostname(), Port: u.Port(), Username: defaultUser, Password: defaultPass}
		switch u.Scheme {
		case "http":
		case "https":
			e.TLS = true
		default:
			return nil, fmt.Errorf("proxylist: endpoints line %d: scheme %q is not http or https", n, u.Scheme)
		}
		if e.Host == "" || e.Port == "" {
			return nil, fmt.Errorf("proxylist: endpoints line %d: need host:port, got %q", n, line)
		}
		if u.User != nil {
			e.Username = u.User.Username()
			e.Password, _ = u.User.Password()
		}
		if label == "" {
			label = e.Addr()
		}
		if seen[label] {
			return nil, fmt.Errorf("proxylist: endpoints line %d: duplicate location %q", n, label)
		}
		seen[label] = true
		e.Label = label
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("proxylist: endpoints: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("proxylist: endpoints: no upstream listed")
	}
	return out, nil
}

func loadPool() ([]Endpoint, error) {
	acct, err := accounts.Current(name)
	if err != nil {
		return nil, err
	}
	text, err := acct.RequireRaw(fieldEndpoints)
	if err != nil {
		return nil, err
	}
	user, _ := acct.Line(accounts.FieldUsername)
	pass, _ := acct.Line(accounts.FieldPassword)
	return ParseEndpoints(text, user, pass)
}

// ---- VPNProvider ------------------------------------------------------

// Login parses the account's endpoint list. There is no vendor session:
// a bad list is the only way to "fail login", and it fails loudly.
func (ProxyList) Login(context.Context) error {
	p, err := loadPool()
	if err != nil {
		mu.Lock()
		loggedIn = false
		mu.Unlock()
		return err
	}
	mu.Lock()
	pool, loggedIn = p, true
	mu.Unlock()
	shared.Debugf("[proxylist] %d upstream(s) loaded", len(p))
	return nil
}

func (ProxyList) Logout(context.Context) error {
	mu.Lock()
	pool, loggedIn, active = nil, false, nil
	mu.Unlock()
	if srv != nil {
		srv.SetDialer(disconnectedDialer)
	}
	return nil
}

func (ProxyList) LoggedIn(context.Context) bool {
	mu.Lock()
	defer mu.Unlock()
	return loggedIn
}

func (ProxyList) Locations(context.Context) []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(pool))
	for _, e := range pool {
		out = append(out, e.Label)
	}
	return out
}

// Connect points the in-process proxy at the upstream named by location
// (empty = random). Status.IP stays empty: the exit IP is whatever the
// upstream egresses from, and the caller's contract probe reads it back
// through this very dialer.
func (ProxyList) Connect(ctx context.Context, location string) provider.Status {
	if srv == nil {
		return provider.Status{Connected: false, Provider: name}
	}
	mu.Lock()
	candidates := pool
	mu.Unlock()
	if len(candidates) == 0 {
		shared.Debugf("[proxylist] connect: no upstreams (not logged in)")
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	var chosen *Endpoint
	want := strings.TrimSpace(location)
	if want == "" {
		e := candidates[rand.Intn(len(candidates))]
		chosen = &e
	} else {
		for i := range candidates {
			if candidates[i].Label == want {
				e := candidates[i]
				chosen = &e
				break
			}
		}
	}
	if chosen == nil {
		shared.Debugf("[proxylist] connect: unknown location %q", want)
		return provider.Status{Connected: false, Provider: name, Location: want}
	}
	srv.SetDialer(makeUpstreamDialer(*chosen))
	mu.Lock()
	active = chosen
	mu.Unlock()
	shared.Debugf("[proxylist] connected via %s (%s, tls=%v)", chosen.Addr(), chosen.Label, chosen.TLS)
	return provider.Status{Connected: true, Provider: name, Location: chosen.Label, Region: chosen.Label}
}

func (ProxyList) Disconnect(context.Context) error {
	mu.Lock()
	active = nil
	mu.Unlock()
	if srv != nil {
		srv.SetDialer(disconnectedDialer) // fail closed; no direct-dial leak
	}
	return nil
}

func (ProxyList) Connected(context.Context) bool {
	mu.Lock()
	defer mu.Unlock()
	return active != nil
}

func (ProxyList) Status(context.Context) provider.Status {
	mu.Lock()
	defer mu.Unlock()
	if active == nil {
		return provider.Status{Connected: false, Provider: name}
	}
	return provider.Status{Connected: true, Provider: name, Location: active.Label, Region: active.Label}
}

func (ProxyList) ActiveLocation(context.Context) string {
	mu.Lock()
	defer mu.Unlock()
	if active == nil {
		return ""
	}
	return active.Label
}

func (ProxyList) Version(context.Context) (string, error) {
	return "proxylist (upstream CONNECT chain)", nil
}

// ---- upstream dialer --------------------------------------------------

// makeUpstreamDialer returns a DialFunc that tunnels a target through e:
// TCP (→ TLS when e.TLS) → CONNECT target with Proxy-Authorization when
// the endpoint has credentials → splice.
func makeUpstreamDialer(e Endpoint) proxy.DialFunc {
	authHeader := ""
	if e.Username != "" || e.Password != "" {
		authHeader = "Proxy-Authorization: Basic " +
			base64.StdEncoding.EncodeToString([]byte(e.Username+":"+e.Password)) + "\r\n"
	}
	addr := e.Addr()
	return func(ctx context.Context, target string) (net.Conn, error) {
		dctx, cancel := context.WithTimeout(ctx, proxyDialTimeout)
		defer cancel()

		var d net.Dialer
		conn, err := d.DialContext(dctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("proxylist upstream dial %s: %w", addr, err)
		}
		if e.TLS {
			tconn := tls.Client(conn, &tls.Config{ServerName: e.Host, RootCAs: tlsRootCAs})
			if err := tconn.HandshakeContext(dctx); err != nil {
				conn.Close()
				return nil, fmt.Errorf("proxylist upstream TLS %s: %w", addr, err)
			}
			conn = tconn
		}
		if dl, ok := dctx.Deadline(); ok {
			_ = conn.SetDeadline(dl)
		}
		req := "CONNECT " + target + " HTTP/1.1\r\n" +
			"Host: " + target + "\r\n" +
			authHeader +
			"Proxy-Connection: keep-alive\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxylist upstream CONNECT write: %w", err)
		}
		br := bufio.NewReader(conn)
		status, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxylist upstream CONNECT response: %w", err)
		}
		if !strings.Contains(status, " 200 ") {
			conn.Close()
			return nil, fmt.Errorf("proxylist upstream %s CONNECT %s: %s", addr, target, strings.TrimSpace(status))
		}
		for { // consume the rest of the response headers
			line, err := br.ReadString('\n')
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("proxylist upstream CONNECT headers: %w", err)
			}
			if strings.TrimSpace(line) == "" {
				break
			}
		}
		_ = conn.SetDeadline(time.Time{}) // clear; proxy sets the tunnel deadline
		return &bufferedConn{Conn: conn, r: br}, nil
	}
}

// bufferedConn lets the spliced tunnel read through the bufio.Reader
// used to parse the CONNECT response, so no buffered bytes are dropped.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// resetForTest clears package state between tests.
func resetForTest() {
	mu.Lock()
	pool, loggedIn, active = nil, false, nil
	mu.Unlock()
	srv = nil
	_ = os.Unsetenv("PROXYLIST_ENDPOINTS")
}
