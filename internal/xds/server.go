package xds

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	server "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
)

// NodeID is the envoy node identifier the pod-local envoy MUST present in
// its bootstrap config (node: { id: tundler-tunnel, cluster: tundler-tunnel }).
// The snapshot cache is keyed by this string; envoy and tundler-tunnel
// must agree.
const NodeID = "tundler-tunnel"

// Server is a thin wrapper around go-control-plane's snapshot cache +
// gRPC server. Exposes a single high-level operation, PushExitIP, that
// rebuilds the LDS+CDS snapshot with the new exit IP and propagates it
// to the connected envoy within ~100ms.
//
// One Server instance per tunnel pod. Started by main in a goroutine
// before login (so envoy can connect early); PushExitIP called by the
// StateTracker.RecordTunnelUp listener after each successful tunnel-up.
type Server struct {
	pod   PodInputs
	cache cachev3.SnapshotCache

	mu       sync.Mutex // guards lastExitIP for diagnostic exposure
	lastExit string
}

// NewServer creates a Server seeded with an empty snapshot (no exit IP
// yet) so envoy can connect and start its xDS stream before the first
// tunnel-up. The empty exit IP just means the x-tundler-exit-ip
// response header is omitted from upstream responses until the first
// PushExitIP arrives.
func NewServer(pod PodInputs) (*Server, error) {
	c := cachev3.NewSnapshotCache(false, cachev3.IDHash{}, nil)
	snap, err := BuildSnapshot(VersionFromTime(time.Now()), pod, "")
	if err != nil {
		return nil, fmt.Errorf("initial snapshot: %w", err)
	}
	if err := c.SetSnapshot(context.Background(), NodeID, snap); err != nil {
		return nil, fmt.Errorf("set initial snapshot: %w", err)
	}
	return &Server{pod: pod, cache: c}, nil
}

// Serve binds to addr (typically 127.0.0.1:18000 — loopback only, per the
// design's tunnel-pod envoy config section) and serves the ADS protocol
// plus the per-resource discovery services. Blocks until the listener
// errors or ctx is cancelled (graceful stop).
func (s *Server) Serve(ctx context.Context, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	gs := grpc.NewServer()
	srv := server.NewServer(ctx, s.cache, nil)
	// Register both the aggregated discovery service AND the per-type
	// services. Envoy bootstraps via ADS but the per-type endpoints are
	// useful for debugging via grpcurl + standard envoy clients.
	discovery.RegisterAggregatedDiscoveryServiceServer(gs, srv)
	listenerservice.RegisterListenerDiscoveryServiceServer(gs, srv)
	cluster.RegisterClusterDiscoveryServiceServer(gs, srv)
	route.RegisterRouteDiscoveryServiceServer(gs, srv)
	endpoint.RegisterEndpointDiscoveryServiceServer(gs, srv)

	go func() {
		<-ctx.Done()
		gs.GracefulStop()
	}()

	log.Printf("xds: gRPC server listening on %s", addr)
	if err := gs.Serve(lis); err != nil {
		return fmt.Errorf("grpc serve: %w", err)
	}
	return nil
}

// PushExitIP rebuilds the snapshot with the new exit IP and stores it.
// envoy receives the update on its open xDS stream within ~100ms. Safe
// to call concurrently — the underlying SnapshotCache is internally
// synchronized.
//
// Called by tundler-tunnel from StateTracker.RecordTunnelUp after each
// successful Connect (initial connect, watchdog reconnect, rotation).
func (s *Server) PushExitIP(exitIP string) error {
	version := VersionFromTime(time.Now())
	snap, err := BuildSnapshot(version, s.pod, exitIP)
	if err != nil {
		return fmt.Errorf("build snapshot: %w", err)
	}
	if err := s.cache.SetSnapshot(context.Background(), NodeID, snap); err != nil {
		return fmt.Errorf("set snapshot: %w", err)
	}
	s.mu.Lock()
	s.lastExit = exitIP
	s.mu.Unlock()
	return nil
}

// LastExitIP returns the last value passed to PushExitIP. Exposed for
// diagnostics (tests + /status) — production code shouldn't depend on
// this for correctness; the source of truth is StateTracker.
func (s *Server) LastExitIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastExit
}
