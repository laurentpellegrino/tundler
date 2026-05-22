// Package xds builds envoy xDS snapshots for the tundler-tunnel pod-local
// envoy. The pod-local envoy uses dynamic LDS+CDS+RDS via ADS from
// localhost:18000 (this package's server). Each successful tunnel-up
// produces a new Snapshot that updates the x-tundler-exit-ip response
// header — see architecture-tundler-fleet-controller.md "Tunnel-pod
// envoy config" for the full design.
//
// This package is also reusable by tundler-fleet-controller for the
// hub-Pod envoy. The two binaries push different resource sets via this
// same machinery (per Decision Q14 in the design doc).
package xds

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	dfpcluster "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	dfpcommon "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	dfpfilter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	routerpb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// PodInputs is everything the SnapshotBuilder needs to assemble an xDS
// snapshot for one tunnel pod. Static-for-pod-lifetime values (pod name,
// node IP) and the rotation-changing exit IP are split so the caller can
// hold onto a builder + just supply a new exit IP on each rotation.
type PodInputs struct {
	PodName        string // POD_NAME from downward API → x-tundler-tunnel-id
	NodeIP         string // node external IP from k8s API → x-tundler-node-ip
	DataListenPort int    // envoy listens on this port for crawl traffic (8484)
}

// BuildSnapshot composes a complete LDS+CDS+RDS snapshot for a tundler-
// tunnel pod-local envoy. The exit IP is included as a response header
// so the crawler (via the hub envoy) can attribute responses to the
// specific tunnel that served them.
//
// `version` must be unique per snapshot (or envoy will ignore the push
// as a no-op). Callers typically use time.Now().UnixNano() formatted as
// a string.
//
// `currentExitIP` is the exit IP of the freshly-established tunnel;
// pushed on every tunnel-up (initial connect + each rotation).
func BuildSnapshot(version string, pod PodInputs, currentExitIP string) (*cachev3.Snapshot, error) {
	if pod.PodName == "" {
		return nil, errors.New("PodInputs.PodName is required")
	}
	if pod.DataListenPort == 0 {
		return nil, errors.New("PodInputs.DataListenPort is required")
	}

	cl, err := buildCluster()
	if err != nil {
		return nil, fmt.Errorf("build cluster: %w", err)
	}
	rc := buildRouteConfiguration(pod.PodName, pod.NodeIP, currentExitIP)
	ln, err := buildListener(pod.DataListenPort, rc)
	if err != nil {
		return nil, fmt.Errorf("build listener: %w", err)
	}

	snap, err := cachev3.NewSnapshot(version, map[resource.Type][]types.Resource{
		resource.ClusterType:  {cl},
		resource.ListenerType: {ln},
	})
	if err != nil {
		return nil, fmt.Errorf("cache.NewSnapshot: %w", err)
	}
	return snap, nil
}

// buildCluster returns a dynamic_forward_proxy cluster — envoy resolves
// the destination from the request (CONNECT target or Host header) and
// opens a connection to it. The VPN tunnel's kernel routing (default
// route through tun0) ensures egress packets go through the VPN exit IP.
//
// We can't use ORIGINAL_DST here: ORIGINAL_DST reads SO_ORIGINAL_DST
// from iptables-redirected sockets, but the crawler is using envoy as
// an explicit HTTP proxy — there's no iptables redirect upstream of
// envoy, so SO_ORIGINAL_DST is empty. dynamic_forward_proxy resolves
// hostnames lazily and works for both regular HTTP requests (where
// the Host header carries the target) and CONNECT requests (where the
// authority carries it).
// dnsCacheConfig is the SINGLE source of truth for the dynamic_forward_proxy
// DNS cache settings. Both the cluster (buildCluster) and the HTTP filter
// (buildListener) reference the cache by name; envoy treats them as the
// same logical cache and rejects the listener if the two definitions
// differ in any setting (name + lookup family + resolver list all
// compared bytewise). Keep them in sync via this one constructor.
func dnsCacheConfig() *dfpcommon.DnsCacheConfig {
	return &dfpcommon.DnsCacheConfig{
		Name:            "dynamic_forward_proxy_cache",
		DnsLookupFamily: cluster.Cluster_V4_ONLY,
		DnsResolutionConfig: &core.DnsResolutionConfig{
			Resolvers: []*core.Address{
				{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
					Address:       "1.1.1.1",
					PortSpecifier: &core.SocketAddress_PortValue{PortValue: 53},
				}}},
				{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
					Address:       "8.8.8.8",
					PortSpecifier: &core.SocketAddress_PortValue{PortValue: 53},
				}}},
			},
		},
	}
}

func buildCluster() (*cluster.Cluster, error) {
	// Pin DNS to public resolvers (Cloudflare + Google), routed through
	// tun0 like any other egress. Without this envoy uses the kernel
	// resolver via /etc/resolv.conf — and the VPN providers (ExpressVPN
	// in particular) sometimes inject DNS entries that the tunnel can't
	// actually reach, surfacing as UnresolvedAddressException storms in
	// the crawler client. Pinning the resolver to 1.1.1.1 / 8.8.8.8
	// keeps DNS lookups inside the VPN tunnel (still anonymous from
	// example's perspective) but on a server that's always reachable.
	dfpCfg, err := anypb.New(&dfpcluster.ClusterConfig{
		ClusterImplementationSpecifier: &dfpcluster.ClusterConfig_DnsCacheConfig{
			DnsCacheConfig: dnsCacheConfig(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("anypb.New(ClusterConfig): %w", err)
	}
	return &cluster.Cluster{
		Name:           ClusterName,
		LbPolicy:       cluster.Cluster_CLUSTER_PROVIDED,
		ConnectTimeout: durationpb.New(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_ClusterType{ClusterType: &cluster.Cluster_CustomClusterType{
			Name:        "envoy.clusters.dynamic_forward_proxy",
			TypedConfig: dfpCfg,
		}},
	}, nil
}

// ClusterName is the upstream-cluster name referenced by the route. Kept
// as a constant so the snapshot's route + cluster stay in sync.
const ClusterName = "vpn-upstream"

// buildRouteConfiguration returns the route table for the listener.
// One virtual host catches all domains; one route forwards to the
// ORIGINAL_DST cluster. ResponseHeadersToAdd attaches the
// x-tundler-tunnel-id / x-tundler-node-ip / x-tundler-exit-ip headers
// so the hub envoy (which sets x-vpn-* from these) can attribute each
// response to its tunnel pod.
func buildRouteConfiguration(podName, nodeIP, exitIP string) *route.RouteConfiguration {
	headers := []*core.HeaderValueOption{
		{Header: &core.HeaderValue{Key: "x-tundler-tunnel-id", Value: podName}},
	}
	if nodeIP != "" {
		headers = append(headers, &core.HeaderValueOption{
			Header: &core.HeaderValue{Key: "x-tundler-node-ip", Value: nodeIP},
		})
	}
	if exitIP != "" {
		headers = append(headers, &core.HeaderValueOption{
			Header: &core.HeaderValue{Key: "x-tundler-exit-ip", Value: exitIP},
		})
	}
	// Two routes:
	//  1. CONNECT (HTTPS forward-proxy): the hub envoy forwards the
	//     CONNECT verb here, this envoy terminates it (connect_config: {})
	//     and TCP-tunnels to the dynamic-forward-proxy-resolved upstream.
	//  2. prefix:/ (plain HTTP forward-proxy): regular HTTP requests
	//     route to the same cluster, which uses the Host header.
	connectRoute := &route.Route{
		Match: &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_ConnectMatcher_{ConnectMatcher: &route.RouteMatch_ConnectMatcher{}},
		},
		Action: &route.Route_Route{
			Route: &route.RouteAction{
				ClusterSpecifier: &route.RouteAction_Cluster{Cluster: ClusterName},
				UpgradeConfigs: []*route.RouteAction_UpgradeConfig{{
					UpgradeType:   "CONNECT",
					ConnectConfig: &route.RouteAction_UpgradeConfig_ConnectConfig{},
				}},
			},
		},
		ResponseHeadersToAdd: headers,
	}
	plainRoute := &route.Route{
		Match: &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"},
		},
		Action: &route.Route_Route{
			Route: &route.RouteAction{
				ClusterSpecifier: &route.RouteAction_Cluster{Cluster: ClusterName},
			},
		},
		ResponseHeadersToAdd: headers,
	}
	return &route.RouteConfiguration{
		Name: "tundler_tunnel_routes",
		VirtualHosts: []*route.VirtualHost{{
			Name:    "all",
			Domains: []string{"*"},
			Routes:  []*route.Route{connectRoute, plainRoute},
		}},
	}
}

// buildListener assembles the :8484 data-plane listener that holds the
// HTTP connection manager. The HCM is the entry point for crawl traffic
// from the hub envoy; routes are inline in the listener (no separate RDS
// resource needed at this scale).
func buildListener(port int, rc *route.RouteConfiguration) (*listener.Listener, error) {
	routerAny, err := anypb.New(&routerpb.Router{})
	if err != nil {
		return nil, fmt.Errorf("anypb.New(Router): %w", err)
	}
	// dynamic_forward_proxy HTTP filter shares the same DnsCacheConfig
	// name as the cluster; that's how envoy wires them together. Without
	// this filter, plain-HTTP requests would get "cluster not found" —
	// the filter resolves the Host header and primes the cluster's DNS
	// cache. CONNECT requests don't need it (envoy bypasses HTTP filters
	// for upgraded streams), but it's harmless to leave installed.
	dfpFilterAny, err := anypb.New(&dfpfilter.FilterConfig{
		ImplementationSpecifier: &dfpfilter.FilterConfig_DnsCacheConfig{
			DnsCacheConfig: dnsCacheConfig(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("anypb.New(dfp FilterConfig): %w", err)
	}
	hcmCfg := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "ingress_http",
		// upgrade_configs: [CONNECT] lets envoy accept HTTP/1.1 CONNECT
		// from the hub envoy (which forwards the crawler's CONNECT
		// verb unmodified). The matching route (connect_matcher) terminates
		// the CONNECT and TCP-tunnels via the dynamic_forward_proxy cluster.
		UpgradeConfigs: []*hcm.HttpConnectionManager_UpgradeConfig{{
			UpgradeType: "CONNECT",
		}},
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: rc,
		},
		HttpFilters: []*hcm.HttpFilter{
			{
				Name:       "envoy.filters.http.dynamic_forward_proxy",
				ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: dfpFilterAny},
			},
			{
				Name:       "envoy.filters.http.router",
				ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerAny},
			},
		},
	}
	hcmAny, err := anypb.New(hcmCfg)
	if err != nil {
		return nil, fmt.Errorf("anypb.New(HttpConnectionManager): %w", err)
	}
	return &listener.Listener{
		Name: "data_listener",
		Address: &core.Address{Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Address:       "0.0.0.0",
				PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(port)},
			},
		}},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: hcmAny,
				},
			}},
		}},
	}, nil
}

// VersionFromTime returns a snapshot version string derived from t.
// Convention is monotonic-ish nanoseconds; envoy uses string equality
// for change detection so any unique non-empty string works.
func VersionFromTime(t time.Time) string {
	return strconv.FormatInt(t.UnixNano(), 10)
}
