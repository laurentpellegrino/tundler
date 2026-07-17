package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// End-to-end over the REAL wire format a client uses: plain HTTP in, target
// named by header, upstream fetched over an impersonated (uTLS) connection.
// The backend is TLS-only + h2, so these tests would fail outright if the
// upstream leg were ever anything but https — which is the guarantee that
// matters, since that leg is what the edge sees.
//
// This shape of test is deliberate: the previous design failed in production
// precisely because the Go-only tests drove the handler with a client that
// spoke a different wire format than the real one. Here the client is an
// ordinary HTTPS client — exactly what the crawler is.
func startFetchServer(t *testing.T, backendHost string) (*ImpersonateServer, string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	var d net.Dialer
	srv := NewImpersonateServer(addr, "tundler-tunnel-expressvpn-0",
		// Upstream dial: send every target to the test backend.
		func(ctx context.Context, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", backendHost)
		})
	srv.transport.insecure = true // backend uses a self-signed httptest cert

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	waitListening(t, addr)
	return srv, addr
}

func TestImpersonateServer_FetchesUpstreamOverHTTPS(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" {
			t.Errorf("upstream Host = %q, want example.com (target header must drive it)", r.Host)
		}
		if got := r.Header.Get(TargetHostHeader); got != "" {
			t.Errorf("%s leaked upstream: %q", TargetHostHeader, got)
		}
		if r.ProtoMajor != 2 {
			t.Errorf("upstream proto = %d, want HTTP/2", r.ProtoMajor)
		}
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.WriteHeader(207)
		_, _ = io.WriteString(w, "body:"+r.URL.RawQuery)
	}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	_, addr := startFetchServer(t, bu.Host)

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/8.8.8.8?q=1", nil)
	req.Header.Set(TargetHostHeader, "example.com")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("fetch via server: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 207 {
		t.Fatalf("status = %d, want 207 relayed from upstream", resp.StatusCode)
	}
	if string(body) != "body:q=1" {
		t.Fatalf("body = %q, want the upstream body relayed", body)
	}
	if resp.Header.Get("X-Echo-Path") != "/8.8.8.8" {
		t.Fatalf("path not relayed upstream: %q", resp.Header.Get("X-Echo-Path"))
	}
}

// A missing/hostile target header must be rejected, not pasted into the URL.
func TestImpersonateServer_RejectsBadTargetHeader(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be reached for a bad target header")
	}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	_, addr := startFetchServer(t, bu.Host)
	client := &http.Client{}

	for _, tc := range []struct{ name, hdr string }{
		{"missing", ""},
		{"with scheme", "https://example.com"},
		{"with path", "example.com/evil"},
		{"with port", "example.com:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/x", nil)
			if tc.hdr != "" {
				req.Header.Set(TargetHostHeader, tc.hdr)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestPickProfile_ServerReportsItsBrowser(t *testing.T) {
	s := NewImpersonateServer("127.0.0.1:0", "tundler-tunnel-mullvad-0", nil)
	if s.Profile() == "" || !strings.Contains(s.Profile(), "-") {
		t.Fatalf("Profile() = %q, want a real browser preset name", s.Profile())
	}
	var _ utls.ClientHelloID = s.hello
}

// --- test helpers ---

func waitListening(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server never listened on %s", addr)
}
