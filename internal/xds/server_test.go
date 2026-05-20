package xds

import (
	"context"
	"net"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

// TestNewServer_HasInitialSnapshot: the cache is seeded with an empty-
// exit-IP snapshot at construction so envoy can connect immediately
// without waiting for the first tunnel-up.
func TestNewServer_HasInitialSnapshot(t *testing.T) {
	srv, err := NewServer(PodInputs{
		PodName:        "tundler-tunnel-expressvpn-3",
		NodeIP:         "128.140.80.11",
		DataListenPort: 8484,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	snap, err := srv.cache.GetSnapshot(NodeID)
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if len(snap.GetResources(resource.ClusterType)) != 1 {
		t.Errorf("got %d clusters in initial snapshot, want 1", len(snap.GetResources(resource.ClusterType)))
	}
	if len(snap.GetResources(resource.ListenerType)) != 1 {
		t.Errorf("got %d listeners in initial snapshot, want 1", len(snap.GetResources(resource.ListenerType)))
	}

	if got := srv.LastExitIP(); got != "" {
		t.Errorf("initial LastExitIP=%q, want empty", got)
	}
}

// TestPushExitIP_UpdatesSnapshot: after PushExitIP, the cached snapshot
// reflects the new exit IP and the cluster + listener resources are
// still present. Version string changes between consecutive pushes.
func TestPushExitIP_UpdatesSnapshot(t *testing.T) {
	srv, err := NewServer(PodInputs{
		PodName:        "tundler-tunnel-expressvpn-3",
		DataListenPort: 8484,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	snap0, _ := srv.cache.GetSnapshot(NodeID)
	v0 := snap0.GetVersion(resource.ListenerType)

	// Force a non-trivial wait so the version (nanosecond timestamp) is
	// guaranteed to differ between the initial snapshot and this push.
	time.Sleep(2 * time.Millisecond)

	if err := srv.PushExitIP("45.83.124.18"); err != nil {
		t.Fatalf("PushExitIP: %v", err)
	}
	if got := srv.LastExitIP(); got != "45.83.124.18" {
		t.Errorf("LastExitIP=%q, want 45.83.124.18", got)
	}

	snap1, _ := srv.cache.GetSnapshot(NodeID)
	v1 := snap1.GetVersion(resource.ListenerType)
	if v0 == v1 {
		t.Errorf("listener version unchanged between snapshots: %q", v0)
	}

	// Cluster + listener both still present.
	if _, ok := snap1.GetResources(resource.ClusterType)[ClusterName].(*cluster.Cluster); !ok {
		t.Error("cluster missing after push")
	}
	if _, ok := snap1.GetResources(resource.ListenerType)["data_listener"].(*listener.Listener); !ok {
		t.Error("listener missing after push")
	}
}

// TestServe_StartsAndStops: the gRPC server binds to a free port and
// stops cleanly when the context is cancelled. Smoke test — actual
// envoy-client conversation is integration-test material.
func TestServe_StartsAndStops(t *testing.T) {
	srv, err := NewServer(PodInputs{
		PodName:        "tundler-tunnel-expressvpn-3",
		DataListenPort: 8484,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Pick a free port on loopback. Closing the listener releases it
	// back to the OS before Serve binds — there's a tiny race window,
	// but for a unit test it's plenty reliable on Linux.
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := probe.Addr().String()
	probe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, addr) }()

	// Wait for the server to actually accept connections, then cancel.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	for {
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		select {
		case <-dialCtx.Done():
			cancel()
			<-done
			t.Fatalf("server never accepted on %s: %v", addr, err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after context cancel")
	}
}
