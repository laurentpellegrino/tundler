package warpproxy

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"testing"

	"github.com/laurentpellegrino/tundler/internal/shared/ovpn"
)

// script is a dial func that returns the given errors in order (nil =
// a connected tunnel) and counts its calls.
type script struct {
	results []error
	calls   int
	tunnel  *ovpn.Tunnel
}

func (s *script) dial() (*ovpn.Tunnel, error) {
	err := s.results[s.calls]
	s.calls++
	if err != nil {
		return nil, err
	}
	return s.tunnel, nil
}

func newScript(t *testing.T, results ...error) *script {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := ovpn.NewForTest(cmd)
	t.Cleanup(func() { _ = tunnel.Stop(context.Background()) })
	return &script{results: results, tunnel: tunnel}
}

var errProxy = fmt.Errorf("Test OpenVPN connection timed out: %w", ovpn.ErrProxyFailed)

func TestDialThroughReconnectsOnceWhenTheProxyCannotReachTheServer(t *testing.T) {
	s := newScript(t, errProxy, nil)
	reconnects := 0
	tunnel, err := dialThrough(context.Background(), s.dial, func(context.Context) error { reconnects++; return nil })
	if err != nil || tunnel != s.tunnel {
		t.Fatalf("the dial on the new session must be returned: tunnel=%v err=%v", tunnel, err)
	}
	if s.calls != 2 || reconnects != 1 {
		t.Fatalf("dials=%d reconnects=%d, want 2 and 1", s.calls, reconnects)
	}
}

func TestDialThroughLeavesOtherOutcomesAlone(t *testing.T) {
	for name, first := range map[string]error{"connected": nil, "credentials": ovpn.ErrAuthFailed, "timeout": errors.New("Test OpenVPN connection timed out")} {
		s := newScript(t, first)
		tunnel, err := dialThrough(context.Background(), s.dial, func(context.Context) error {
			t.Fatalf("%s: a session must not be replaced unless the proxy failed", name)
			return nil
		})
		if !errors.Is(err, first) || (first == nil) != (tunnel != nil) || s.calls != 1 {
			t.Fatalf("%s: tunnel=%v err=%v dials=%d", name, tunnel, err, s.calls)
		}
	}
}

func TestDialThroughKeepsTheProxyFailureWhenNoNewSessionStarts(t *testing.T) {
	s := newScript(t, errProxy)
	tunnel, err := dialThrough(context.Background(), s.dial, func(context.Context) error { return errors.New("warp connect: exit status 1") })
	if tunnel != nil || !errors.Is(err, ovpn.ErrProxyFailed) || s.calls != 1 {
		t.Fatalf("tunnel=%v err=%v dials=%d, want the proxy failure after one dial", tunnel, err, s.calls)
	}
}

func TestDialThroughBlamesTheServerWhenANewSessionCannotReachItEither(t *testing.T) {
	s := newScript(t, errProxy, errProxy)
	tunnel, err := dialThrough(context.Background(), s.dial, func(context.Context) error { return nil })
	if tunnel != nil || err == nil || errors.Is(err, ovpn.ErrProxyFailed) {
		t.Fatalf("tunnel=%v err=%v, want a plain failure: the session is no longer the suspect", tunnel, err)
	}
	if s.calls != 2 {
		t.Fatalf("dials=%d, want 2: one session replacement per connect", s.calls)
	}
}
