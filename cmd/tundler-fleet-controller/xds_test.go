package main

import (
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

func TestBuildFleetSnapshot_OneClusterPerProviderWithEndpoints(t *testing.T) {
	configured := map[string]int{
		"expressvpn": 7,
		"nordvpn":    9,
	}
	podAddrs := map[string][]string{
		"expressvpn": {"10.0.0.1", "10.0.0.2"},
		"nordvpn":    {"10.0.1.1"},
	}
	snap, err := buildFleetSnapshot("v1", configured, podAddrs)
	if err != nil {
		t.Fatalf("buildFleetSnapshot: %v", err)
	}
	clusters := snap.GetResources(resource.ClusterType)
	endpoints := snap.GetResources(resource.EndpointType)
	if got, want := len(clusters), 2; got != want {
		t.Errorf("len(clusters)=%d, want %d", got, want)
	}
	if got, want := len(endpoints), 2; got != want {
		t.Errorf("len(endpoints)=%d, want %d", got, want)
	}
	c, ok := clusters["tundler-tunnel-expressvpn"].(*cluster.Cluster)
	if !ok {
		t.Fatalf("tundler-tunnel-expressvpn cluster missing or wrong type")
	}
	if c.GetType() != cluster.Cluster_EDS {
		t.Errorf("cluster.Type=%v, want EDS", c.GetType())
	}
	if c.GetLbPolicy() != cluster.Cluster_ROUND_ROBIN {
		t.Errorf("cluster.LbPolicy=%v, want ROUND_ROBIN", c.GetLbPolicy())
	}
	if c.GetEdsClusterConfig().GetServiceName() != "tundler-tunnel-expressvpn" {
		t.Errorf("ServiceName=%q, want tundler-tunnel-expressvpn", c.GetEdsClusterConfig().GetServiceName())
	}
	if c.GetOutlierDetection().GetConsecutiveGatewayFailure().GetValue() != 5 {
		t.Errorf("ConsecutiveGatewayFailure=%d, want 5",
			c.GetOutlierDetection().GetConsecutiveGatewayFailure().GetValue())
	}
	if c.GetEdsClusterConfig().GetEdsConfig().GetConfigSourceSpecifier() == nil {
		t.Error("EdsConfig.ConfigSourceSpecifier is nil, want ADS")
	}
	if _, ok := c.GetEdsClusterConfig().GetEdsConfig().GetConfigSourceSpecifier().(*core.ConfigSource_Ads); !ok {
		t.Errorf("EdsConfig.ConfigSourceSpecifier type=%T, want *ConfigSource_Ads",
			c.GetEdsClusterConfig().GetEdsConfig().GetConfigSourceSpecifier())
	}

	ep, ok := endpoints["tundler-tunnel-expressvpn"].(*endpoint.ClusterLoadAssignment)
	if !ok {
		t.Fatalf("tundler-tunnel-expressvpn ClusterLoadAssignment missing or wrong type")
	}
	if got := len(ep.GetEndpoints()[0].GetLbEndpoints()); got != 2 {
		t.Errorf("expressvpn LbEndpoints=%d, want 2", got)
	}
	sa := ep.GetEndpoints()[0].GetLbEndpoints()[0].GetEndpoint().GetAddress().GetSocketAddress()
	if sa.GetAddress() != "10.0.0.1" {
		t.Errorf("first endpoint ip=%q, want 10.0.0.1 (sorted)", sa.GetAddress())
	}
	if sa.GetPortValue() != tunnelDataPort {
		t.Errorf("endpoint port=%d, want %d", sa.GetPortValue(), tunnelDataPort)
	}
}

func TestBuildFleetSnapshot_ProviderWithNoEndpointsStillExportsCluster(t *testing.T) {
	// A configured provider with zero ready pods must STILL appear in CDS,
	// with an empty EDS — that way envoy preserves the cluster name and
	// resumes routing the moment the first pod becomes Ready, without
	// needing a re-discovery roundtrip.
	configured := map[string]int{"surfshark": 15}
	podAddrs := map[string][]string{} // empty
	snap, err := buildFleetSnapshot("v1", configured, podAddrs)
	if err != nil {
		t.Fatalf("buildFleetSnapshot: %v", err)
	}
	clusters := snap.GetResources(resource.ClusterType)
	endpoints := snap.GetResources(resource.EndpointType)
	if len(clusters) != 1 {
		t.Errorf("len(clusters)=%d, want 1 even with no endpoints", len(clusters))
	}
	if len(endpoints) != 1 {
		t.Errorf("len(endpoints)=%d, want 1 even with no endpoints", len(endpoints))
	}
	ep := endpoints["tundler-tunnel-surfshark"].(*endpoint.ClusterLoadAssignment)
	if got := len(ep.GetEndpoints()[0].GetLbEndpoints()); got != 0 {
		t.Errorf("LbEndpoints=%d for empty provider, want 0", got)
	}
}

func TestBuildFleetSnapshot_DeterministicForGivenInputs(t *testing.T) {
	configured := map[string]int{"a": 1, "b": 1, "c": 1}
	podAddrs := map[string][]string{
		"a": {"10.0.0.3", "10.0.0.1", "10.0.0.2"}, // unsorted
		"b": {"10.0.1.1"},
	}
	snap1, err := buildFleetSnapshot("v1", configured, podAddrs)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	snap2, err := buildFleetSnapshot("v1", configured, podAddrs)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	// Sort-then-compare endpoint IP order for cluster "a" — must match
	// across invocations (= sorted ascending).
	get := func(s any) []string {
		ep := s.(*endpoint.ClusterLoadAssignment)
		out := []string{}
		for _, lbe := range ep.GetEndpoints()[0].GetLbEndpoints() {
			out = append(out, lbe.GetEndpoint().GetAddress().GetSocketAddress().GetAddress())
		}
		return out
	}
	g1 := get(snap1.GetResources(resource.EndpointType)["tundler-tunnel-a"])
	g2 := get(snap2.GetResources(resource.EndpointType)["tundler-tunnel-a"])
	if !equalSlices(g1, g2) {
		t.Errorf("non-deterministic output: %v vs %v", g1, g2)
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !equalSlices(g1, want) {
		t.Errorf("got=%v, want sorted %v", g1, want)
	}
}

func TestFleetXDSServer_RebuildAdvancesVersion(t *testing.T) {
	fc := newFleetController(map[string]int{"expressvpn": 7})
	s := newFleetXDSServer(fc)
	if err := s.rebuildSnapshot(); err != nil {
		t.Fatalf("first rebuild: %v", err)
	}
	v1 := s.lastVersionForTest()
	if v1 == "" {
		t.Fatal("version is empty after first rebuild")
	}
	// Ensure the clock moves so subsequent rebuilds get a new version.
	time.Sleep(2 * time.Millisecond)
	if err := s.rebuildSnapshot(); err != nil {
		t.Fatalf("second rebuild: %v", err)
	}
	v2 := s.lastVersionForTest()
	if v2 == v1 {
		t.Errorf("version did not advance: %q == %q", v1, v2)
	}
}

func TestFleetXDSServer_ReflectsFleetControllerCacheChanges(t *testing.T) {
	fc := newFleetController(map[string]int{"expressvpn": 7})
	fc.applyProviderReconcile("expressvpn", "tundler-tunnel-expressvpn",
		[]string{"10.0.0.1"},
		[]string{"tundler-tunnel-expressvpn-0"},
	)
	s := newFleetXDSServer(fc)
	if err := s.rebuildSnapshot(); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	snap, err := s.cache.GetSnapshot(fleetXDSNodeID)
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	endpoints := snap.GetResources(resource.EndpointType)
	ep := endpoints["tundler-tunnel-expressvpn"].(*endpoint.ClusterLoadAssignment)
	if got := len(ep.GetEndpoints()[0].GetLbEndpoints()); got != 1 {
		t.Errorf("LbEndpoints=%d, want 1", got)
	}

	// Now add a second pod via the reconcile method — rebuildSnapshot
	// should reflect the new endpoint.
	fc.applyProviderReconcile("expressvpn", "tundler-tunnel-expressvpn",
		[]string{"10.0.0.1", "10.0.0.2"},
		[]string{"tundler-tunnel-expressvpn-0", "tundler-tunnel-expressvpn-1"},
	)
	if err := s.rebuildSnapshot(); err != nil {
		t.Fatalf("second rebuild: %v", err)
	}
	snap, _ = s.cache.GetSnapshot(fleetXDSNodeID)
	endpoints = snap.GetResources(resource.EndpointType)
	ep = endpoints["tundler-tunnel-expressvpn"].(*endpoint.ClusterLoadAssignment)
	if got := len(ep.GetEndpoints()[0].GetLbEndpoints()); got != 2 {
		t.Errorf("after second reconcile: LbEndpoints=%d, want 2", got)
	}
}
