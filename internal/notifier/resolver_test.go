package notifier

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laurentpellegrino/tundler/internal/clusterdns"
)

func TestParseNameservers(t *testing.T) {
	in := `# kubelet-written
search ipregistry-production.svc.cluster.local svc.cluster.local cluster.local
nameserver 10.0.96.10
nameserver 10.0.96.10 ; duplicate
nameserver fd00::53
nameserver not-an-ip
options ndots:5
`
	got := parseNameservers(strings.NewReader(in))
	want := []string{"10.0.96.10:53", "[fd00::53]:53"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parseNameservers = %v, want %v", got, want)
	}
	if got := parseNameservers(strings.NewReader("search example\n")); len(got) != 0 {
		t.Fatalf("expected no nameservers, got %v", got)
	}
}

func TestLoadClusterResolver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")

	t.Setenv(clusterdns.EnvResolvConf, path)
	if c := loadClusterResolver(); c != nil {
		t.Fatalf("expected nil resolver for a missing file, got %v", c.nameservers)
	}

	if err := os.WriteFile(path, []byte("nameserver 10.0.96.10\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := loadClusterResolver()
	if c == nil || len(c.nameservers) != 1 || c.nameservers[0] != "10.0.96.10:53" {
		t.Fatalf("unexpected resolver: %+v", c)
	}
	if c.source != path {
		t.Fatalf("source = %q, want %q", c.source, path)
	}

	if err := os.WriteFile(path, []byte("# nothing usable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := loadClusterResolver(); c != nil {
		t.Fatalf("expected nil resolver for a file without nameservers, got %v", c.nameservers)
	}
}

// listen returns a loopback TCP listener that accepts and immediately
// closes connections, plus its port.
func listen(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return ln, port
}

func TestDialContextResolvesThroughClusterLookup(t *testing.T) {
	_, port := listen(t)
	c := newClusterResolver("test", []string{"10.0.96.10:53"})
	var asked string
	c.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		asked = host
		// IPv6 first on purpose: the dialer must prefer the IPv4 address.
		return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	conn, err := c.dialContext(context.Background(), "tcp", "collector.svc.cluster.local:"+port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if asked != "collector.svc.cluster.local" {
		t.Fatalf("lookup asked for %q", asked)
	}
	if host, _, _ := net.SplitHostPort(conn.RemoteAddr().String()); host != "127.0.0.1" {
		t.Fatalf("dialed %s, want the IPv4 candidate", conn.RemoteAddr())
	}
}

func TestDialContextIPLiteralSkipsLookup(t *testing.T) {
	_, port := listen(t)
	c := newClusterResolver("test", []string{"10.0.96.10:53"})
	c.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		t.Fatal("lookup must not run for an IP literal")
		return nil, nil
	}
	conn, err := c.dialContext(context.Background(), "tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
}

func TestDialContextLookupFailure(t *testing.T) {
	c := newClusterResolver("test", []string{"10.0.96.10:53"})
	c.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("no such host")
	}
	_, err := c.dialContext(context.Background(), "tcp", "collector.svc.cluster.local:8080")
	if err == nil || !strings.Contains(err.Error(), "10.0.96.10:53") || !strings.Contains(err.Error(), "no such host") {
		t.Fatalf("expected a lookup error naming the nameserver, got %v", err)
	}
}

func TestDialContextFallsBackToLastGoodAnswer(t *testing.T) {
	_, port := listen(t)
	c := newClusterResolver("test", []string{"10.0.96.10:53"})
	fail := false
	c.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		if fail {
			return nil, errors.New("write udp: operation not permitted")
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	conn, err := c.dialContext(context.Background(), "tcp", "collector.svc.cluster.local:"+port)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	conn.Close()
	fail = true
	conn, err = c.dialContext(context.Background(), "tcp", "collector.svc.cluster.local:"+port)
	if err != nil {
		t.Fatalf("dial after lookup failure should use the last good answer: %v", err)
	}
	conn.Close()
	// A host that never resolved still fails.
	if _, err := c.dialContext(context.Background(), "tcp", "other.svc.cluster.local:"+port); err == nil {
		t.Fatal("expected an error for a host with no cached answer")
	}
}
