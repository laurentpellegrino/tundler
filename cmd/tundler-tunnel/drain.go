package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/laurentpellegrino/tundler/internal/proxy"
)

// drainController is the contract the rotator uses to bleed in-flight
// CONNECT tunnels before tearing the VPN down. Two steps:
//
//	TriggerGracefulDrain — flip the proxy into drain mode so new
//	    CONNECTs get 503; existing tunnels keep going.
//	WaitForActiveConnectionsToDrain — poll the proxy's open-tunnel
//	    count until it reaches 0 or the hard timeout elapses.
//
// Both steps run BEFORE the VPN daemon Disconnect, so requests don't
// land on a half-torn-down tunnel.
//
// Injected via interface so production wires it to the in-process
// proxy.Server while tests use a fake controller that records calls.
type drainController interface {
	TriggerGracefulDrain(ctx context.Context) error
	WaitForActiveConnectionsToDrain(ctx context.Context, timeout time.Duration) error
}

// proxyDrainController is the production drainController, backed by
// the in-process Go CONNECT proxy.
type proxyDrainController struct {
	srv *proxy.Server
}

func newProxyDrainController(srv *proxy.Server) *proxyDrainController {
	return &proxyDrainController{srv: srv}
}

// TriggerGracefulDrain flips the proxy into drain mode. Subsequent
// CONNECTs get a 503; existing tunnels drain naturally.
func (c *proxyDrainController) TriggerGracefulDrain(_ context.Context) error {
	c.srv.SetDraining(true)
	return nil
}

// WaitForActiveConnectionsToDrain polls the proxy's OpenTunnels stat
// every 500ms until it reaches 0 (drained) or timeout elapses.
// Returns nil on drained, ctx error on cancellation, or
// errDrainTimeout if the hard timeout fired while open > 0. After
// the wait completes (success or timeout), drain mode is cleared so
// the proxy can accept again post-reconnect.
func (c *proxyDrainController) WaitForActiveConnectionsToDrain(ctx context.Context, timeout time.Duration) error {
	defer c.srv.SetDraining(false)
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if open := c.srv.Stats().OpenTunnels; open == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w (last active=%d)", errDrainTimeout, c.srv.Stats().OpenTunnels)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// errDrainTimeout is returned when the hard timeout fires with
// in-flight tunnels still > 0. Rotator callers proceed to Disconnect
// anyway — the crawler's slot retry catches anything that survives.
var errDrainTimeout = errors.New("drain wait timed out with active connections > 0")
