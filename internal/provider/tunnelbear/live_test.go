package tunnelbear

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/proxy"
)

// TestLiveConnectAndEgress drives the full Go path against the real
// TunnelBear control plane + edge: Login → Connect → dial a target
// through the installed proxy dialer → confirm egress is the edge IP
// (not the machine's own). Skipped unless TUNNELBEAR_USERNAME /
// TUNNELBEAR_PASSWORD are set, so CI/`go test ./...` stays offline.
//
//	TUNNELBEAR_USERNAME=… TUNNELBEAR_PASSWORD=… \
//	  go test -run TestLiveConnectAndEgress -tags provider_tunnelbear -v ./internal/provider/tunnelbear/
func TestLiveConnectAndEgress(t *testing.T) {
	if os.Getenv("TUNNELBEAR_USERNAME") == "" || os.Getenv("TUNNELBEAR_PASSWORD") == "" {
		t.Skip("set TUNNELBEAR_USERNAME and TUNNELBEAR_PASSWORD to run the live test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s := proxy.New("127.0.0.1:0", "live-test", "0.0.0.0")
	tb := TunnelBear{}
	tb.AttachProxy(s)

	if err := tb.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	st := tb.Connect(ctx, "us")
	if !st.Connected || st.IP == "" {
		t.Fatalf("Connect: not connected: %+v", st)
	}
	t.Logf("connected: edge IP=%s location=%s region=%s", st.IP, st.Location, st.Region)

	// Probe egress THROUGH the installed dialer (the crawler's path).
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(c context.Context, _, addr string) (net.Conn, error) {
			conn, ok, err := s.DialUpstream(c, addr)
			if !ok {
				t.Fatalf("no upstream dialer installed after Connect")
			}
			return conn, err
		},
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 15 * time.Second}).
		Get("https://checkip.amazonaws.com")
	if err != nil {
		t.Fatalf("egress probe through edge: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	egress := strings.TrimSpace(string(body))
	t.Logf("egress through TunnelBear edge: %s", egress)

	if egress != st.IP {
		t.Errorf("egress %s != edge IP %s (proxy not routing as expected)", egress, st.IP)
	}
	if net.ParseIP(egress) == nil {
		t.Errorf("egress %q is not a valid IP", egress)
	}
}
