package main

import (
	"sync"
)

// FleetController is the in-memory cache that drives both the crawler-facing
// /status response (counts of healthy vs configured pods per provider) and
// the xDS snapshot pushed to the pod-local hub envoy (CDS + EDS for the
// per-provider tunnel clusters).
//
// All fields are guarded by mu. Readers (HTTP /status, snapshot rebuild)
// take RLock; the informer reconcile and the vpn-providers.yaml fsnotify
// watch take Lock when they mutate.
type FleetController struct {
	mu sync.RWMutex

	// configured: provider name -> max_tunnels from vpn-providers.yaml.
	// Rebuilt on every ConfigMap reload (fsnotify); identifies the
	// universe of providers the hub envoy should know about.
	configured map[string]int

	// healthy: provider name -> count of Ready=true pod IPs currently in
	// the EndpointSlice cache. Mirrors len(podAddrs[provider]) — kept as
	// a separate field so /status doesn't have to walk a slice.
	healthy map[string]int

	// podAddrs: provider name -> []podIP (Ready=true only). Pushed into
	// EDS as the cluster's endpoint set on every rebuildSnapshot.
	podAddrs map[string][]string

	// podToService: podName (= tunnel_id) -> governing-service name.
	// Used by /rotate to compose the stable per-pod DNS hostname when
	// forwarding to the tunnel pod's :4242/rotate endpoint.
	podToService map[string]string
}

func newFleetController(configured map[string]int) *FleetController {
	return &FleetController{
		configured:   configured,
		healthy:      map[string]int{},
		podAddrs:     map[string][]string{},
		podToService: map[string]string{},
	}
}

// serviceForTunnelID returns the governing headless-Service name for a
// given pod (the tunnel_id), or ok=false if the pod isn't in any
// vpn-tunnel-* EndpointSlice subset (unknown name, crashed, evicted).
func (f *FleetController) serviceForTunnelID(tunnelID string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	svc, ok := f.podToService[tunnelID]
	return svc, ok
}

// statusSnapshot composes the JSON-serializable view returned by /status.
// Lays out providers explicitly so callers see every configured provider,
// even ones with zero healthy pods (a 0/N row is itself a useful signal).
func (f *FleetController) statusSnapshot() statusPayload {
	f.mu.RLock()
	defer f.mu.RUnlock()
	providers := make(map[string]providerStatus, len(f.configured))
	totalHealthy, totalConfigured := 0, 0
	for p, cfg := range f.configured {
		h := f.healthy[p]
		providers[p] = providerStatus{Healthy: h, Configured: cfg}
		totalHealthy += h
		totalConfigured += cfg
	}
	return statusPayload{
		Providers:       providers,
		TotalHealthy:    totalHealthy,
		TotalConfigured: totalConfigured,
	}
}

// statusPayload matches the response schema documented in the design doc's
// "GET /status" section.
type statusPayload struct {
	Providers       map[string]providerStatus `json:"providers"`
	TotalHealthy    int                       `json:"total_healthy"`
	TotalConfigured int                       `json:"total_configured"`
}

type providerStatus struct {
	Healthy    int `json:"healthy"`
	Configured int `json:"configured"`
}
