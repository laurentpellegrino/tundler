package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/laurentpellegrino/tundler/internal/proxy"
)

func TestProxyDrainController_TriggerSetsDraining(t *testing.T) {
	srv := proxy.New("placeholder", "pod", "")
	dc := newProxyDrainController(srv)
	if err := dc.TriggerGracefulDrain(context.Background()); err != nil {
		t.Fatalf("TriggerGracefulDrain: %v", err)
	}
	if !srv.IsDraining() {
		t.Fatal("expected proxy to be in draining mode after TriggerGracefulDrain")
	}
}

func TestProxyDrainController_WaitReturnsNilWhenAlreadyEmpty(t *testing.T) {
	srv := proxy.New("placeholder", "pod", "")
	dc := newProxyDrainController(srv)
	// No open tunnels — should return nil immediately and clear drain.
	srv.SetDraining(true)
	err := dc.WaitForActiveConnectionsToDrain(context.Background(), 100*time.Millisecond)
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
	if srv.IsDraining() {
		t.Fatal("expected drain flag to be cleared after wait")
	}
}

func TestProxyDrainController_WaitTimesOutWithActiveTunnels(t *testing.T) {
	srv := proxy.New("placeholder", "pod", "")
	dc := newProxyDrainController(srv)
	// Simulate an open tunnel — proxy.Server exposes this via the
	// IncOpenTunnels test helper so we don't need real network IO.
	srv.IncOpenTunnels(1)
	defer srv.IncOpenTunnels(-1)
	err := dc.WaitForActiveConnectionsToDrain(context.Background(), 50*time.Millisecond)
	if !errors.Is(err, errDrainTimeout) {
		t.Fatalf("expected errDrainTimeout, got: %v", err)
	}
	if srv.IsDraining() {
		t.Fatal("expected drain flag cleared even on timeout")
	}
}
