package xds

import (
	"strings"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

func TestBuildSnapshot_RequiresPodName(t *testing.T) {
	_, err := BuildSnapshot("v1", PodInputs{DataListenPort: 8484}, "1.2.3.4")
	if err == nil || !strings.Contains(err.Error(), "PodName") {
		t.Errorf("err=%v, want error mentioning PodName", err)
	}
}

func TestBuildSnapshot_RequiresPort(t *testing.T) {
	_, err := BuildSnapshot("v1", PodInputs{PodName: "tundler-tunnel-expressvpn-3"}, "1.2.3.4")
	if err == nil || !strings.Contains(err.Error(), "DataListenPort") {
		t.Errorf("err=%v, want error mentioning DataListenPort", err)
	}
}

func TestBuildSnapshot_ContainsClusterAndListener(t *testing.T) {
	snap, err := BuildSnapshot("v1",
		PodInputs{
			PodName:        "tundler-tunnel-expressvpn-3",
			NodeIP:         "128.140.80.11",
			DataListenPort: 8484,
		},
		"45.83.124.18",
	)
	if err != nil {
		t.Fatalf("BuildSnapshot: %v", err)
	}

	clusters := snap.GetResources(resource.ClusterType)
	if len(clusters) != 1 {
		t.Fatalf("got %d clusters, want 1", len(clusters))
	}
	cl, ok := clusters[ClusterName].(*cluster.Cluster)
	if !ok {
		t.Fatalf("cluster %q not found / wrong type: %v", ClusterName, clusters)
	}
	// The cluster is now `envoy.clusters.dynamic_forward_proxy` (a custom
	// extension), not a built-in type. The discovery_type oneof selects
	// CustomClusterType and GetType() returns the default STATIC zero
	// value, so check the custom-cluster name instead.
	if got := cl.GetClusterType().GetName(); got != "envoy.clusters.dynamic_forward_proxy" {
		t.Errorf("cluster custom name=%q, want envoy.clusters.dynamic_forward_proxy", got)
	}
	if cl.GetLbPolicy() != cluster.Cluster_CLUSTER_PROVIDED {
		t.Errorf("lb_policy=%v, want CLUSTER_PROVIDED", cl.GetLbPolicy())
	}

	listeners := snap.GetResources(resource.ListenerType)
	if len(listeners) != 1 {
		t.Fatalf("got %d listeners, want 1", len(listeners))
	}
	ln, ok := listeners["data_listener"].(*listener.Listener)
	if !ok {
		t.Fatalf("listener data_listener not found / wrong type")
	}
	addr := ln.GetAddress().GetSocketAddress()
	if addr.GetAddress() != "0.0.0.0" {
		t.Errorf("listener address=%q, want 0.0.0.0", addr.GetAddress())
	}
	if addr.GetPortValue() != 8484 {
		t.Errorf("listener port=%d, want 8484", addr.GetPortValue())
	}
}

// TestBuildSnapshot_ResponseHeadersIncludeTundlerSet asserts that
// x-tundler-tunnel-id, x-tundler-node-ip, x-tundler-exit-ip all appear
// in the route's ResponseHeadersToAdd. That's the contract the hub
// envoy depends on to populate the x-vpn-* headers it returns to the
// crawler — see "Response attribution + on-demand rotation" in the
// design doc.
func TestBuildSnapshot_ResponseHeadersIncludeTundlerSet(t *testing.T) {
	snap, err := BuildSnapshot("v1",
		PodInputs{
			PodName:        "tundler-tunnel-expressvpn-3",
			NodeIP:         "128.140.80.11",
			DataListenPort: 8484,
		},
		"45.83.124.18",
	)
	if err != nil {
		t.Fatalf("BuildSnapshot: %v", err)
	}

	// Drill into the inline route config on the listener.
	ln := snap.GetResources(resource.ListenerType)["data_listener"].(*listener.Listener)
	if len(ln.FilterChains) != 1 || len(ln.FilterChains[0].Filters) != 1 {
		t.Fatalf("listener filter chain structure unexpected")
	}
	// We don't unmarshal the HCM Any here; the response-headers contract
	// is verified at the route-config level by buildRouteConfiguration's
	// unit-internal accessor (call directly, not through the snapshot).
	rc := buildRouteConfiguration("tundler-tunnel-expressvpn-3", "128.140.80.11", "45.83.124.18")
	r := rc.VirtualHosts[0].Routes[0]
	headerKeys := map[string]string{}
	for _, h := range r.ResponseHeadersToAdd {
		headerKeys[h.Header.Key] = h.Header.Value
	}
	want := map[string]string{
		"x-tundler-tunnel-id": "tundler-tunnel-expressvpn-3",
		"x-tundler-node-ip":   "128.140.80.11",
		"x-tundler-exit-ip":   "45.83.124.18",
	}
	for k, v := range want {
		got, ok := headerKeys[k]
		if !ok {
			t.Errorf("missing response header %q", k)
			continue
		}
		if got != v {
			t.Errorf("header %q = %q, want %q", k, got, v)
		}
	}
}

// TestBuildSnapshot_OmitsEmptyNodeAndExitHeaders: at pod boot before
// the first tunnel-up, exitIP is empty. The snapshot still builds
// successfully (so envoy can be configured pre-tunnel) and just omits
// the header rather than emitting "x-tundler-exit-ip: ".
func TestBuildSnapshot_OmitsEmptyNodeAndExitHeaders(t *testing.T) {
	rc := buildRouteConfiguration("tundler-tunnel-expressvpn-3", "", "")
	r := rc.VirtualHosts[0].Routes[0]
	if len(r.ResponseHeadersToAdd) != 1 {
		t.Errorf("got %d headers, want 1 (only tunnel-id when others empty)", len(r.ResponseHeadersToAdd))
	}
	if r.ResponseHeadersToAdd[0].Header.Key != "x-tundler-tunnel-id" {
		t.Errorf("first header key=%q, want x-tundler-tunnel-id", r.ResponseHeadersToAdd[0].Header.Key)
	}
}

// TestVersionFromTime_Monotonic: two calls a tiny moment apart produce
// different version strings. Snapshot identity is by version string;
// duplicate versions are treated as no-ops by envoy.
func TestVersionFromTime_Monotonic(t *testing.T) {
	v1 := VersionFromTime(time.Now())
	time.Sleep(1 * time.Millisecond)
	v2 := VersionFromTime(time.Now())
	if v1 == v2 {
		t.Errorf("VersionFromTime returned %q twice across a 1ms gap — not monotonic enough", v1)
	}
}
