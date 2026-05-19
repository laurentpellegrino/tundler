package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// drainController is the contract the rotator uses to perform Layer 1 +
// Layer 2 of the three-defense-layer rotation flow:
//
//	Layer 1: TriggerGracefulDrain — tells envoy to stop accepting NEW
//	         downstream connections. Any incoming TCP connect gets
//	         refused at the pod-local envoy within milliseconds.
//	Layer 2: WaitForActiveConnectionsToDrain — polls envoy admin until
//	         downstream_cx_active reaches 0 (in-flight requests have
//	         completed) or the hard timeout elapses.
//
// Both steps run BEFORE the VPN daemon Disconnect, so requests don't
// land on a half-torn-down tunnel.
//
// Injected via interface so production wires it to a real envoy on
// 127.0.0.1:9901 while tests use a fake controller that records calls.
type drainController interface {
	TriggerGracefulDrain(ctx context.Context) error
	WaitForActiveConnectionsToDrain(ctx context.Context, timeout time.Duration) error
}

// envoyDrainController is the production implementation that talks to
// envoy admin via HTTP. adminURL is "http://127.0.0.1:9901" in prod
// (loopback-only per the design's envoy admin bind decision).
type envoyDrainController struct {
	adminURL string
}

func newEnvoyDrainController(adminURL string) *envoyDrainController {
	return &envoyDrainController{adminURL: adminURL}
}

// TriggerGracefulDrain hits envoy's admin endpoint that fails new
// listener health checks. Envoy starts refusing new TCP connections
// within milliseconds; existing connections drain naturally.
func (c *envoyDrainController) TriggerGracefulDrain(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.adminURL+"/drain_listeners?graceful", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST /drain_listeners: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("envoy admin /drain_listeners status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// WaitForActiveConnectionsToDrain polls envoy /stats every 500ms for
// downstream_cx_active to reach 0. Returns nil on drained, ctx error on
// cancellation, or errDrainTimeout if the timeout elapsed with active
// connections still > 0 (rotation proceeds anyway in that case).
func (c *envoyDrainController) WaitForActiveConnectionsToDrain(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		active, err := c.fetchActiveConnections(ctx)
		if err == nil && active == 0 {
			return nil
		}
		if err != nil {
			// Log + continue; transient admin-endpoint hiccups
			// shouldn't kill the rotation.
			log.Printf("tundler-tunnel: drain wait: stats fetch error (will retry): %v", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w (last active=%d)", errDrainTimeout, active)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// errDrainTimeout is returned by WaitForActiveConnectionsToDrain when
// the hard timeout fires with in-flight connections still > 0. Rotator
// callers proceed to Disconnect anyway — the design's Layer 3 (hub
// envoy retry) catches anything that survives the drain timeout.
var errDrainTimeout = errors.New("drain wait timed out with active connections > 0")

// fetchActiveConnections sums downstream_cx_active across all listeners.
// Envoy reports a counter per listener; for a single-listener tunnel
// pod (`data_listener`) this is just the one value.
func (c *envoyDrainController) fetchActiveConnections(ctx context.Context) (int64, error) {
	url := c.adminURL + "/stats?format=json&filter=listener\\..*\\.downstream_cx_active"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("envoy admin /stats status %d", resp.StatusCode)
	}
	var body struct {
		Stats []struct {
			Name  string      `json:"name"`
			Value json.Number `json:"value"`
		} `json:"stats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("decode envoy stats: %w", err)
	}
	var total int64
	for _, s := range body.Stats {
		v, err := s.Value.Int64()
		if err != nil {
			return 0, fmt.Errorf("parse %s value %q: %w", s.Name, s.Value, err)
		}
		total += v
	}
	return total, nil
}
