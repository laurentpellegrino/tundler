package clusterdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

type call struct {
	name string
	args string
}

// recorder fakes iptables: every -D succeeds `stale` times per rule, then
// fails like the real binary does once no copy is left.
type recorder struct {
	calls   []call
	stale   int
	deleted map[string]int
	failIns bool
}

func (r *recorder) run(_ context.Context, name string, args ...string) error {
	joined := strings.Join(args, " ")
	r.calls = append(r.calls, call{name, joined})
	switch {
	case strings.Contains(joined, " -D OUTPUT "):
		if r.deleted == nil {
			r.deleted = map[string]int{}
		}
		key := joined[strings.Index(joined, "-D OUTPUT "):]
		if r.deleted[key] < r.stale {
			r.deleted[key]++
			return nil
		}
		return errors.New("iptables: Bad rule (does a matching rule exist in that chain?)")
	case strings.Contains(joined, " -I OUTPUT 1 "):
		if r.failIns {
			return errors.New("iptables: Permission denied")
		}
		return nil
	}
	return errors.New("unexpected call " + joined)
}

func TestParseNameservers(t *testing.T) {
	in := "search ipregistry-production.svc.cluster.local\nnameserver 10.0.96.10 # cluster\nnameserver 10.0.96.10\nnameserver fd00::53\nnameserver not-an-ip\noptions ndots:5\n"
	got := ParseNameservers(strings.NewReader(in))
	if len(got) != 2 || got[0].String() != "10.0.96.10" || got[1].String() != "fd00::53" {
		t.Fatalf("got %v", got)
	}
}

func TestAllowRemovesStaleCopiesThenInsertsAtHead(t *testing.T) {
	rec := &recorder{stale: 2}
	ns := []net.IP{net.ParseIP("10.0.96.10"), net.ParseIP("fd00::53")}
	if err := Allow(context.Background(), ns, rec.run); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	// Per nameserver and protocol: 2 successful deletes, 1 failing delete, 1 insert.
	if want := 2 * 2 * 4; len(rec.calls) != want {
		t.Fatalf("got %d calls, want %d:\n%v", len(rec.calls), want, rec.calls)
	}
	seqUDP := []string{
		"-w 5 -D OUTPUT -o eth0 -d 10.0.96.10 -p udp --dport 53 -j ACCEPT",
		"-w 5 -D OUTPUT -o eth0 -d 10.0.96.10 -p udp --dport 53 -j ACCEPT",
		"-w 5 -D OUTPUT -o eth0 -d 10.0.96.10 -p udp --dport 53 -j ACCEPT",
		"-w 5 -I OUTPUT 1 -o eth0 -d 10.0.96.10 -p udp --dport 53 -j ACCEPT",
	}
	for i, want := range seqUDP {
		if rec.calls[i].name != "iptables" || rec.calls[i].args != want {
			t.Fatalf("call %d = %s %s, want iptables %s", i, rec.calls[i].name, rec.calls[i].args, want)
		}
	}
	if got := rec.calls[7]; got.name != "iptables" || got.args != "-w 5 -I OUTPUT 1 -o eth0 -d 10.0.96.10 -p tcp --dport 53 -j ACCEPT" {
		t.Fatalf("tcp insert = %v", got)
	}
	if got := rec.calls[15]; got.name != "ip6tables" || !strings.HasSuffix(got.args, "-I OUTPUT 1 -o eth0 -d fd00::53 -p tcp --dport 53 -j ACCEPT") {
		t.Fatalf("ip6tables insert = %v", got)
	}
}

func TestAllowReportsInsertFailures(t *testing.T) {
	rec := &recorder{failIns: true}
	err := Allow(context.Background(), []net.IP{net.ParseIP("10.0.96.10")}, rec.run)
	if err == nil || !strings.Contains(err.Error(), "udp to 10.0.96.10") || !strings.Contains(err.Error(), "tcp to 10.0.96.10") {
		t.Fatalf("expected both inserts reported, got %v", err)
	}
}

func TestAllowNoNameserversIsNoop(t *testing.T) {
	rec := &recorder{}
	if err := Allow(context.Background(), nil, rec.run); err != nil || len(rec.calls) != 0 {
		t.Fatalf("err=%v calls=%v", err, rec.calls)
	}
}

func TestAllowDeleteLoopIsBounded(t *testing.T) {
	rec := &recorder{stale: 1000}
	if err := Allow(context.Background(), []net.IP{net.ParseIP("10.0.96.10")}, rec.run); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if len(rec.calls) != 2*(maxDeletes+1) {
		t.Fatalf("got %d calls, want %d", len(rec.calls), 2*(maxDeletes+1))
	}
}
