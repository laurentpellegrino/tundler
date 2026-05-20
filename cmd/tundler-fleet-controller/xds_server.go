package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	xdsserver "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
)

// fleetXDSAddr is where the hub-Pod envoy connects to fetch CDS+EDS.
// Loopback-only by design (envoy and fleet-controller share the Pod).
const fleetXDSAddr = "127.0.0.1:18000"

// fleetXDSServer wraps go-control-plane's SnapshotCache + a gRPC server.
// One instance per fleet-controller process. The sliceWatcher's
// onReconcile callback drives rebuildSnapshot(), which composes a fresh
// CDS+EDS Snapshot from the current FleetController state and stores it
// — envoy receives the update on its open ADS stream within ~100ms.
type fleetXDSServer struct {
	fc    *FleetController
	cache cachev3.SnapshotCache

	mu          sync.Mutex // serializes rebuildSnapshot so two reconciles can't race on the same version string
	lastVersion string
}

func newFleetXDSServer(fc *FleetController) *fleetXDSServer {
	return &fleetXDSServer{
		fc:    fc,
		cache: cachev3.NewSnapshotCache(false, cachev3.IDHash{}, nil),
	}
}

// rebuildSnapshot composes a new CDS+EDS Snapshot from the current
// FleetController state and stores it under fleetXDSNodeID. Safe to
// call concurrently — internal mutex serializes the version-string
// generation so two callers can't produce the same nanosecond.
//
// Called by:
//   - sliceWatcher.onReconcile after every EndpointSlice event (EDS changes)
//   - the fsnotify watcher (Slice 4) after vpn-providers.yaml changes (CDS changes)
//   - main during startup after all informers have synced (initial seed)
func (s *fleetXDSServer) rebuildSnapshot() error {
	s.fc.mu.RLock()
	configured := make(map[string]int, len(s.fc.configured))
	for k, v := range s.fc.configured {
		configured[k] = v
	}
	podAddrs := make(map[string][]string, len(s.fc.podAddrs))
	for k, v := range s.fc.podAddrs {
		cp := make([]string, len(v))
		copy(cp, v)
		podAddrs[k] = cp
	}
	s.fc.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	version := fleetXDSVersion(time.Now())
	// time.Now() at nanosecond precision MAY collide under burst — bump
	// by 1 ns if we already emitted that version.
	if version == s.lastVersion {
		version = fleetXDSVersion(time.Now().Add(time.Nanosecond))
	}
	snap, err := buildFleetSnapshot(version, configured, podAddrs)
	if err != nil {
		return fmt.Errorf("build fleet snapshot: %w", err)
	}
	if err := s.cache.SetSnapshot(context.Background(), fleetXDSNodeID, snap); err != nil {
		return fmt.Errorf("set snapshot: %w", err)
	}
	s.lastVersion = version
	return nil
}

// Serve binds to addr (127.0.0.1:18000 in production) and runs the
// xDS gRPC server. Blocks until the listener errors or ctx is cancelled.
func (s *fleetXDSServer) Serve(ctx context.Context, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	gs := grpc.NewServer()
	srv := xdsserver.NewServer(ctx, s.cache, nil)
	// Hub envoy bootstraps via ADS; we also register the per-type
	// services to support grpcurl-based debugging.
	discovery.RegisterAggregatedDiscoveryServiceServer(gs, srv)
	cluster.RegisterClusterDiscoveryServiceServer(gs, srv)
	endpointservice.RegisterEndpointDiscoveryServiceServer(gs, srv)

	go func() {
		<-ctx.Done()
		gs.GracefulStop()
	}()

	log.Printf("xds (fleet): gRPC server listening on %s", addr)
	if err := gs.Serve(lis); err != nil {
		return fmt.Errorf("grpc serve: %w", err)
	}
	return nil
}

// lastVersionForTest exposes lastVersion to tests in the same package.
// Production code shouldn't depend on it.
func (s *fleetXDSServer) lastVersionForTest() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastVersion
}
