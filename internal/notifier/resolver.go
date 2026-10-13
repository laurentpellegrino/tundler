package notifier

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Cluster-resolver pinning.
//
// Several provider clients (expressvpn, veepn, windscribe) rewrite
// /etc/resolv.conf to an in-tunnel resolver that cannot resolve
// cluster-internal names, and expressvpn's prestart repair swaps in public
// resolvers before tundler-tunnel even starts. Both leave the process
// without any resolver that knows the sink's `*.svc.cluster.local` name,
// so neither a dial-time lookup nor the boot-time pin in pinHost can
// succeed — the 2026-08-13 ExpressVPN outage (every event POST failing
// for two months) was exactly that.
//
// The entrypoint therefore saves the kubelet-written resolv.conf ONCE per
// pod sandbox, before any provider code runs, to a path that survives
// container restarts (/run is a pod-scoped emptyDir). When that file
// exists the notifier resolves sink hostnames through its nameservers
// directly — at dial time, so a sink is never pinned to a stale address
// and a transiently unreachable resolver heals on the next emit. Without
// the file (local dev, non-Kubernetes hosts) the boot-time pin remains
// the fallback.
const (
	envClusterResolvConf     = "TUNDLER_CLUSTER_RESOLV_CONF"
	defaultClusterResolvConf = "/run/tundler/resolv.conf"
	dnsPort                  = "53"
	dnsDialTimeout           = 3 * time.Second
)

type lookupFunc func(ctx context.Context, host string) ([]net.IPAddr, error)

// clusterResolver resolves sink hostnames through the nameservers saved by
// the entrypoint instead of whatever /etc/resolv.conf currently says.
type clusterResolver struct {
	source      string
	nameservers []string // host:port, as handed to net.Dial
	lookup      lookupFunc
	dialer      *net.Dialer
	next        atomic.Uint32
}

// loadClusterResolver reads the saved resolver config and returns nil when
// there is none (file absent, unreadable or without nameservers).
func loadClusterResolver() *clusterResolver {
	path := strings.TrimSpace(os.Getenv(envClusterResolvConf))
	if path == "" {
		path = defaultClusterResolvConf
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	servers := parseNameservers(f)
	if len(servers) == 0 {
		return nil
	}
	return newClusterResolver(path, servers)
}

func newClusterResolver(source string, nameservers []string) *clusterResolver {
	c := &clusterResolver{
		source:      source,
		nameservers: nameservers,
		dialer:      &net.Dialer{Timeout: dnsDialTimeout},
	}
	r := &net.Resolver{
		PreferGo: true,
		// Go's resolver still iterates the servers it read from
		// /etc/resolv.conf, but every attempt is dialed here, where the
		// address it asks for is replaced by one of ours.
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			i := c.next.Add(1) - 1
			return c.dialer.DialContext(ctx, network, c.nameservers[int(i)%len(c.nameservers)])
		},
	}
	c.lookup = r.LookupIPAddr
	return c
}

// parseNameservers extracts the `nameserver` entries of a resolv.conf,
// deduplicated and in file order, each as host:port.
func parseNameservers(r io.Reader) []string {
	var servers []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(fields[1])
		if ip == nil {
			continue
		}
		addr := net.JoinHostPort(ip.String(), dnsPort)
		if !seen[addr] {
			seen[addr] = true
			servers = append(servers, addr)
		}
	}
	return servers
}

// dialContext is the http.Transport dialer: IP literals connect directly,
// hostnames are resolved through the cluster nameservers (IPv4 first) and
// every candidate address is tried before giving up.
func (c *clusterResolver) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) != nil {
		return c.dialer.DialContext(ctx, network, addr)
	}
	addrs, err := c.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s via cluster nameservers %v: %w", host, c.nameservers, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s via cluster nameservers %v: no addresses", host, c.nameservers)
	}
	sort.SliceStable(addrs, func(i, j int) bool {
		return addrs[i].IP.To4() != nil && addrs[j].IP.To4() == nil
	})
	var errs []error
	for _, a := range addrs {
		conn, err := c.dialer.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}
