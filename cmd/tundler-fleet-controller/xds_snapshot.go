package main

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// fleetXDSNodeID is the envoy node identifier the hub-Pod envoy MUST
// present in its bootstrap config (node: { id: tundler-fleet-controller,
// cluster: tundler-fleet-controller }). The snapshot cache is keyed by
// this string; envoy and fleet-controller must agree.
const fleetXDSNodeID = "tundler-fleet-controller"

// tunnelDataPort is the port each tunnel-pod exposes for envoy traffic.
// Matches the EXPOSE in docker/Dockerfile.tunnel and the listener bound
// by tundler-tunnel's xDS snapshot in internal/xds.
const tunnelDataPort = 8484

// buildFleetSnapshot composes a CDS+EDS snapshot for the hub-Pod envoy.
// One Cluster per configured provider (CDS), one ClusterLoadAssignment
// per cluster (EDS) listing the Ready pod IPs from the EndpointSlices
// cache.
//
// Resources are deterministic for any given inputs — clusters and
// endpoints are sorted before assembly so equal inputs produce
// byte-equal snapshots. This keeps test assertions stable and makes
// version-string equality (no-op detection) meaningful.
//
// `version` must be unique per push (or envoy will treat it as a no-op).
// Callers use fleetXDSVersion() in production.
func buildFleetSnapshot(version string, configured map[string]int, podAddrs map[string][]string) (*cachev3.Snapshot, error) {
	providers := make([]string, 0, len(configured))
	for p := range configured {
		providers = append(providers, p)
	}
	sort.Strings(providers)

	cdsResources := make([]types.Resource, 0, len(providers))
	edsResources := make([]types.Resource, 0, len(providers))
	for _, p := range providers {
		clusterName := "tundler-tunnel-" + p
		cdsResources = append(cdsResources, buildFleetCluster(clusterName))

		ips := append([]string{}, podAddrs[p]...)
		sort.Strings(ips)
		edsResources = append(edsResources, buildFleetEndpoints(clusterName, ips))
	}

	snap, err := cachev3.NewSnapshot(version, map[resource.Type][]types.Resource{
		resource.ClusterType:  cdsResources,
		resource.EndpointType: edsResources,
	})
	if err != nil {
		return nil, fmt.Errorf("cache.NewSnapshot: %w", err)
	}
	return snap, nil
}

// buildFleetCluster returns one EDS-backed Cluster definition. ADS is
// declared as the EDS config source so envoy pulls endpoints over the
// same xDS stream it pulls clusters from (no second connection needed).
//
// LB policy is ROUND_ROBIN among the cluster's pods. The
// hub-envoy-level weighted-RR across PROVIDER clusters lives in the
// listener route config (envoy bootstrap), not here.
//
// OutlierDetection ejects a pod from the LB pool after consecutive
// gateway failures — Trigger B in the design doc. The threshold (5
// consecutive failures) intentionally favors stability over twitch:
// transient blips don't depool, but a genuinely broken tunnel is out
// quickly.
func buildFleetCluster(name string) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 name,
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		ConnectTimeout:       durationpb.New(time.Second),
		EdsClusterConfig: &cluster.Cluster_EdsClusterConfig{
			EdsConfig: &core.ConfigSource{
				ResourceApiVersion: core.ApiVersion_V3,
				ConfigSourceSpecifier: &core.ConfigSource_Ads{
					Ads: &core.AggregatedConfigSource{},
				},
			},
			ServiceName: name,
		},
		OutlierDetection: &cluster.OutlierDetection{
			ConsecutiveGatewayFailure: wrapperspb.UInt32(5),
		},
	}
}

// buildFleetEndpoints returns one ClusterLoadAssignment binding pod IPs
// to the named cluster. Each pod is a SocketAddress on tunnelDataPort.
func buildFleetEndpoints(clusterName string, podIPs []string) *endpoint.ClusterLoadAssignment {
	lbEndpoints := make([]*endpoint.LbEndpoint, 0, len(podIPs))
	for _, ip := range podIPs {
		lbEndpoints = append(lbEndpoints, &endpoint.LbEndpoint{
			HostIdentifier: &endpoint.LbEndpoint_Endpoint{
				Endpoint: &endpoint.Endpoint{
					Address: &core.Address{
						Address: &core.Address_SocketAddress{
							SocketAddress: &core.SocketAddress{
								Address: ip,
								PortSpecifier: &core.SocketAddress_PortValue{
									PortValue: tunnelDataPort,
								},
							},
						},
					},
				},
			},
		})
	}
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{{
			LbEndpoints: lbEndpoints,
		}},
	}
}

// fleetXDSVersion returns a snapshot version string derived from t.
// Format mirrors internal/xds.VersionFromTime — nanosecond unix.
func fleetXDSVersion(t time.Time) string {
	return strconv.FormatInt(t.UnixNano(), 10)
}
