package main

import (
	"context"
	"fmt"
	"log"

	"github.com/laurentpellegrino/tundler/internal/provider"
)

// connectTunnel picks a random allowed location (provider.Locations()
// minus `excluded`) and connects through it. On success, records the
// tunnel-up details into state and transitions to StateReady. On failure,
// returns an error; caller decides whether to retry or surrender.
//
// Used by both the initial connect (from main) and the watchdog reconnect
// path (when an unexpected tunnel drop is detected). Same code path keeps
// "first connect" and "reconnect after drop" behaving identically.
//
// State transitions:
//
//	(any) → StateConnecting → (Connect call) → StateReady     (success)
//	                                          → (return error) (failure; caller sets Failed)
func connectTunnel(ctx context.Context, prov provider.VPNProvider, state *StateTracker, providerName string, excluded []string) error {
	state.Set(StateConnecting)
	available := prov.Locations(ctx)
	location, err := pickLocation(available, excluded)
	if err != nil {
		return fmt.Errorf("pick location for provider=%s (%d available, %d excluded): %w",
			providerName, len(available), len(excluded), err)
	}
	log.Printf("tundler-tunnel: provider=%s connecting to location=%s", providerName, location)
	status := prov.Connect(ctx, location)
	if !status.Connected {
		return fmt.Errorf("connect failed for provider=%s location=%s status=%+v",
			providerName, location, status)
	}
	state.RecordTunnelUp(location, status.IP)
	state.Set(StateReady)
	log.Printf("tundler-tunnel: provider=%s tunnel up location=%s exit_ip=%s",
		providerName, location, status.IP)
	return nil
}
