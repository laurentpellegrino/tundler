// Package clusterdns keeps the cluster's own resolver reachable from a
// tunnel pod no matter what firewall the VPN client installs.
//
// Every tunnel pod already treats cluster traffic as special: the
// entrypoint saves the kubelet-written resolv.conf and installs a route
// that sends the cluster CIDR over eth0 instead of the tunnel. DNS to the
// cluster resolver rides that route, but a provider's own firewall can
// still reject it: ExpressVPN arms an `evpn.*` chain set on every connect
// whose blockDNS member REJECTs port 53 to anything but its in-tunnel
// resolver, and it does so with network lock off. tundler-tunnel's event
// hook resolves `*.svc.cluster.local` sink names through the saved
// resolver, so every exit-IP event from the ExpressVPN fleet died on that
// rule (observed 2026-10-19: 203 exit IPs used, 6 delivered).
//
// The fix is one ACCEPT per saved nameserver and protocol, kept at the
// HEAD of OUTPUT so it wins regardless of whether the provider appends or
// prepends its jump. It is asserted by the entrypoint before the VPN comes
// up, by ExpressVPN's prestart before every daemon start, and by the
// tunnel-up listener after every connect (the moment a provider re-arms
// its chains). On providers that never firewall DNS the rule matches
// nothing. It only permits packets to the resolver's private address on
// the cluster interface — traffic the bypass route already carries — so
// it cannot move anything around the tunnel.
package clusterdns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	// EnvResolvConf names the saved resolv.conf; shared with the
	// notifier and the entrypoint.
	EnvResolvConf     = "TUNDLER_CLUSTER_RESOLV_CONF"
	DefaultResolvConf = "/run/tundler/resolv.conf"

	// clusterIface is the pod's cluster-facing interface, the same one
	// the entrypoint pins the bypass route to.
	clusterIface = "eth0"
	// maxDeletes bounds the "remove stale copies" loop so a runner that
	// never fails cannot spin forever.
	maxDeletes = 16
)

var protocols = []string{"udp", "tcp"}

// Runner executes one firewall command. Production uses iptables; tests
// substitute a recorder.
type Runner func(ctx context.Context, name string, args ...string) error

// ResolvConfPath returns the saved resolv.conf location.
func ResolvConfPath() string {
	if p := strings.TrimSpace(os.Getenv(EnvResolvConf)); p != "" {
		return p
	}
	return DefaultResolvConf
}

// ParseNameservers extracts the `nameserver` entries of a resolv.conf,
// deduplicated and in file order. Lines that do not hold an IP literal
// are ignored.
func ParseNameservers(r io.Reader) []net.IP {
	var servers []net.IP
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
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		servers = append(servers, ip)
	}
	return servers
}

// LoadNameservers reads the saved resolv.conf; nil when there is none.
func LoadNameservers(path string) []net.IP {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return ParseNameservers(f)
}

// rule is the OUTPUT-chain match for one nameserver and protocol.
func rule(ns net.IP, proto string) []string {
	return []string{"-o", clusterIface, "-d", ns.String(), "-p", proto, "--dport", "53", "-j", "ACCEPT"}
}

func binaryFor(ns net.IP) string {
	if ns.To4() == nil {
		return "ip6tables"
	}
	return "iptables"
}

// Allow puts an ACCEPT for DNS to every nameserver at the head of
// OUTPUT. Stale copies (from an earlier call, or left at a lower position
// by a provider that prepended its own jump) are removed first so the
// surviving rule is always the first one evaluated. Errors from the
// insert are collected and returned; a failing delete just ends the
// cleanup loop.
func Allow(ctx context.Context, nameservers []net.IP, run Runner) error {
	var errs []error
	for _, ns := range nameservers {
		bin := binaryFor(ns)
		for _, proto := range protocols {
			r := rule(ns, proto)
			for i := 0; i < maxDeletes; i++ {
				if err := run(ctx, bin, append([]string{"-w", "5", "-D", "OUTPUT"}, r...)...); err != nil {
					break
				}
			}
			if err := run(ctx, bin, append([]string{"-w", "5", "-I", "OUTPUT", "1"}, r...)...); err != nil {
				errs = append(errs, fmt.Errorf("%s %s to %s: %w", bin, proto, ns, err))
			}
		}
	}
	return errors.Join(errs...)
}

var (
	skipOnce sync.Once
	skipped  bool
)

// Ensure is the production entry point: loads the saved nameservers and
// asserts the rules with the real iptables. It is a no-op, logged once,
// when the pod has no saved resolv.conf or no iptables binary (local
// runs outside Kubernetes).
func Ensure(ctx context.Context) {
	nameservers := LoadNameservers(ResolvConfPath())
	if len(nameservers) == 0 {
		skipOnce.Do(func() {
			log.Printf("clusterdns: no saved cluster resolver at %s — firewall exception skipped", ResolvConfPath())
		})
		return
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		skipOnce.Do(func() { log.Printf("clusterdns: iptables not available — firewall exception skipped") })
		return
	}
	run := func(ctx context.Context, name string, args ...string) error {
		_, err := shared.RunCmdSilent(ctx, name, args...)
		return err
	}
	if err := Allow(ctx, nameservers, run); err != nil {
		log.Printf("clusterdns: could not allow DNS to cluster resolvers %v: %v", nameservers, err)
		return
	}
	log.Printf("clusterdns: DNS to cluster resolvers %v allowed ahead of any provider firewall", nameservers)
}
