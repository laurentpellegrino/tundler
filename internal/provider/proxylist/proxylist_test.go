package proxylist

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/laurentpellegrino/tundler/internal/proxy"
)

// connectProxy is a minimal HTTP CONNECT proxy for tests: it checks the
// Proxy-Authorization header when wantAuth is set, then splices to the
// target. It records how many CONNECTs it served.
func connectProxy(t *testing.T, wantAuth string, useTLS bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var served atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		if wantAuth != "" && r.Header.Get("Proxy-Authorization") != wantAuth {
			w.Header().Set("Proxy-Authenticate", "Basic")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			up.Close()
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		cl, buf, err := hj.Hijack()
		if err != nil {
			up.Close()
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		_ = buf.Flush()
		served.Add(1)
		go func() { _, _ = io.Copy(up, cl); up.Close() }()
		_, _ = io.Copy(cl, up)
		cl.Close()
	})
	if useTLS {
		return httptest.NewTLSServer(h), &served
	}
	return httptest.NewServer(h), &served
}

// echoTarget accepts one line and echoes it back, so a spliced tunnel can
// be verified end to end.
func echoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				line, _ := bufio.NewReader(c).ReadString('\n')
				_, _ = c.Write([]byte("echo:" + line))
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func roundTrip(t *testing.T, dial proxy.DialFunc, target string) string {
	t.Helper()
	c, err := dial(context.Background(), target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestParseEndpointsAcceptsEveryDocumentedForm(t *testing.T) {
	eps, err := ParseEndpoints(`
# static ISP proxies, shared credential below
10.0.0.1:8080 nyc-1
http://10.0.0.2:8080
https://alice:s3cret@gw.example.net:443 gateway-eu
`, "u", "p")
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 3 {
		t.Fatalf("want 3 endpoints, got %d", len(eps))
	}
	if eps[0].Label != "nyc-1" || eps[0].Username != "u" || eps[0].Password != "p" || eps[0].TLS {
		t.Errorf("labelled plain endpoint parsed as %+v", eps[0])
	}
	if eps[1].Label != "10.0.0.2:8080" {
		t.Errorf("unlabelled endpoint should be named by host:port, got %q", eps[1].Label)
	}
	if !eps[2].TLS || eps[2].Username != "alice" || eps[2].Password != "s3cret" || eps[2].Label != "gateway-eu" {
		t.Errorf("URL credentials/TLS/label not honoured: %+v", eps[2])
	}
}

func TestParseEndpointsRejectsBadLinesLoudly(t *testing.T) {
	for _, bad := range []string{"", "   \n# only comments\n", "socks5://h:1", "no-port", "h:1 a\nh:2 a"} {
		if _, err := ParseEndpoints(bad, "", ""); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestDialerTunnelsThroughPlainAndTLSUpstreamsWithAuth(t *testing.T) {
	target := echoTarget(t)
	auth := basic("user", "pass")

	plain, plainServed := connectProxy(t, auth, false)
	defer plain.Close()
	pu := strings.TrimPrefix(plain.URL, "http://")
	host, port, _ := net.SplitHostPort(pu)
	if got := roundTrip(t, makeUpstreamDialer(Endpoint{Host: host, Port: port, Username: "user", Password: "pass"}), target); got != "echo:ping" {
		t.Fatalf("plain: got %q", got)
	}
	if plainServed.Load() != 1 {
		t.Fatalf("plain upstream served %d CONNECTs, want 1", plainServed.Load())
	}

	secure, secureServed := connectProxy(t, auth, true)
	defer secure.Close()
	pool := x509.NewCertPool()
	pool.AddCert(secure.Certificate())
	tlsRootCAs = pool
	defer func() { tlsRootCAs = nil }()
	su := strings.TrimPrefix(secure.URL, "https://")
	host, port, _ = net.SplitHostPort(su)
	if got := roundTrip(t, makeUpstreamDialer(Endpoint{Host: host, Port: port, TLS: true, Username: "user", Password: "pass"}), target); got != "echo:ping" {
		t.Fatalf("tls: got %q", got)
	}
	if secureServed.Load() != 1 {
		t.Fatalf("tls upstream served %d CONNECTs, want 1", secureServed.Load())
	}
}

func TestDialerSurfacesUpstreamRefusals(t *testing.T) {
	target := echoTarget(t)
	srvp, _ := connectProxy(t, basic("user", "pass"), false)
	defer srvp.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srvp.URL, "http://"))

	_, err := makeUpstreamDialer(Endpoint{Host: host, Port: port, Username: "user", Password: "wrong"})(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("wrong password: want a 407 error, got %v", err)
	}
	_, err = makeUpstreamDialer(Endpoint{Host: "127.0.0.1", Port: "1"})(context.Background(), target)
	if err == nil {
		t.Fatal("closed upstream port: want an error")
	}
}

func TestProviderConnectsRotatesAndFailsClosed(t *testing.T) {
	resetForTest()
	defer resetForTest()
	target := echoTarget(t)
	a, aServed := connectProxy(t, "", false)
	defer a.Close()
	b, bServed := connectProxy(t, "", false)
	defer b.Close()
	os.Setenv("PROXYLIST_ENDPOINTS",
		strings.TrimPrefix(a.URL, "http://")+" alpha\n"+strings.TrimPrefix(b.URL, "http://")+" beta\n")
	defer os.Unsetenv("PROXYLIST_ENDPOINTS")

	p := ProxyList{}
	core := proxy.New("127.0.0.1:0", "tundler-tunnel-proxylist-0", "10.0.0.9")
	p.AttachProxy(core)
	ctx := context.Background()

	if _, ok, err := core.DialUpstream(ctx, target); !ok || err == nil {
		t.Fatalf("before Connect the dialer must fail closed, got ok=%v err=%v", ok, err)
	}
	if err := p.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if locs := p.Locations(ctx); strings.Join(locs, ",") != "alpha,beta" {
		t.Fatalf("locations: %v", locs)
	}

	st := p.Connect(ctx, "alpha")
	if !st.Connected || st.Location != "alpha" || st.IP != "" {
		t.Fatalf("connect alpha: %+v (IP must stay empty so the contract probe fills it)", st)
	}
	dial := func(c context.Context, tgt string) (net.Conn, error) {
		conn, _, err := core.DialUpstream(c, tgt)
		return conn, err
	}
	if got := roundTrip(t, dial, target); got != "echo:ping" {
		t.Fatalf("via alpha: %q", got)
	}
	if aServed.Load() != 1 || bServed.Load() != 0 {
		t.Fatalf("alpha should have served the CONNECT: a=%d b=%d", aServed.Load(), bServed.Load())
	}

	if st := p.Connect(ctx, "beta"); !st.Connected || p.ActiveLocation(ctx) != "beta" {
		t.Fatalf("rotate to beta: %+v", st)
	}
	roundTrip(t, dial, target)
	if bServed.Load() != 1 {
		t.Fatalf("beta should have served the second CONNECT: a=%d b=%d", aServed.Load(), bServed.Load())
	}
	if st := p.Connect(ctx, "gamma"); st.Connected {
		t.Fatal("unknown location must not connect")
	}
	if err := p.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := core.DialUpstream(ctx, target); !ok || err == nil {
		t.Fatal("after Disconnect the dialer must fail closed again")
	}
	if p.Connected(ctx) || p.Status(ctx).Connected {
		t.Fatal("disconnected provider still reports connected")
	}
}
