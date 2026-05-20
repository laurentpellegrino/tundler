package main

import (
	"context"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const testNamespace = "ipregistry-test"

func boolPtr(b bool) *bool { return &b }

func newSlice(name, svcName string, endpoints ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels:    map[string]string{"kubernetes.io/service-name": svcName},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   endpoints,
	}
}

func readyEndpoint(podName, ip string) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses: []string{ip},
		Conditions: discoveryv1.EndpointConditions{
			Ready: boolPtr(true),
		},
		TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: podName, Namespace: testNamespace},
	}
}

func notReadyEndpoint(podName, ip string) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses: []string{ip},
		Conditions: discoveryv1.EndpointConditions{
			Ready: boolPtr(false),
		},
		TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: podName, Namespace: testNamespace},
	}
}

// waitForInitialSync waits for the done channel, with a 5s safety timeout.
func waitForInitialSync(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("informer initial sync did not complete within 5s")
	}
}

// waitForCondition polls the predicate every 20ms up to 2s.
func waitForCondition(t *testing.T, msg string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condition not met within 2s: %s", msg)
}

func TestStartProvider_InitialSyncReadyAndUnreadyEndpoints(t *testing.T) {
	cs := fake.NewSimpleClientset(
		newSlice("vpn-tunnel-expressvpn-abc1", "vpn-tunnel-expressvpn",
			readyEndpoint("vpn-tunnel-expressvpn-0", "10.0.0.1"),
			readyEndpoint("vpn-tunnel-expressvpn-1", "10.0.0.2"),
			notReadyEndpoint("vpn-tunnel-expressvpn-2", "10.0.0.3"),
		),
	)
	fc := newFleetController(map[string]int{"expressvpn": 7})
	w := &sliceWatcher{cs: cs, namespace: testNamespace, fc: fc}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, done := w.startProvider(ctx, "vpn-tunnel-expressvpn", "expressvpn")
	defer stop()
	waitForInitialSync(t, done)

	fc.mu.RLock()
	got := append([]string{}, fc.podAddrs["expressvpn"]...)
	healthy := fc.healthy["expressvpn"]
	svc0, ok0 := fc.podToService["vpn-tunnel-expressvpn-0"]
	_, okNotReady := fc.podToService["vpn-tunnel-expressvpn-2"]
	fc.mu.RUnlock()

	sort.Strings(got)
	if want := []string{"10.0.0.1", "10.0.0.2"}; !equalSlices(got, want) {
		t.Errorf("podAddrs=%v, want %v (not-ready endpoints must be excluded)", got, want)
	}
	if healthy != 2 {
		t.Errorf("healthy=%d, want 2", healthy)
	}
	if !ok0 || svc0 != "vpn-tunnel-expressvpn" {
		t.Errorf("podToService[vpn-tunnel-expressvpn-0]=(%q,%v), want (vpn-tunnel-expressvpn,true)", svc0, ok0)
	}
	if okNotReady {
		t.Error("podToService should not contain the not-ready pod")
	}
}

func TestStartProvider_ReconcileOnUpdate(t *testing.T) {
	cs := fake.NewSimpleClientset(
		newSlice("vpn-tunnel-nordvpn-abc1", "vpn-tunnel-nordvpn",
			readyEndpoint("vpn-tunnel-nordvpn-0", "10.1.0.1"),
		),
	)
	fc := newFleetController(map[string]int{"nordvpn": 9})

	var reconcileCount atomic.Int32
	w := &sliceWatcher{
		cs:          cs,
		namespace:   testNamespace,
		fc:          fc,
		onReconcile: func() { reconcileCount.Add(1) },
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, done := w.startProvider(ctx, "vpn-tunnel-nordvpn", "nordvpn")
	defer stop()
	waitForInitialSync(t, done)

	if got := reconcileCount.Load(); got < 1 {
		t.Errorf("reconcileCount=%d, want >=1 after initial sync", got)
	}

	// Add a second pod via the fake clientset — the informer should
	// pick it up and reconcile.
	_, err := cs.DiscoveryV1().EndpointSlices(testNamespace).Create(
		ctx,
		newSlice("vpn-tunnel-nordvpn-abc2", "vpn-tunnel-nordvpn",
			readyEndpoint("vpn-tunnel-nordvpn-1", "10.1.0.2"),
		),
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("Create EndpointSlice: %v", err)
	}

	waitForCondition(t, "healthy reaches 2", func() bool {
		fc.mu.RLock()
		defer fc.mu.RUnlock()
		return fc.healthy["nordvpn"] == 2
	})

	fc.mu.RLock()
	got := append([]string{}, fc.podAddrs["nordvpn"]...)
	fc.mu.RUnlock()
	sort.Strings(got)
	if want := []string{"10.1.0.1", "10.1.0.2"}; !equalSlices(got, want) {
		t.Errorf("podAddrs=%v, want %v", got, want)
	}
}

func TestStartProvider_PodGoingNotReadyDropsItFromCache(t *testing.T) {
	slice := newSlice("vpn-tunnel-pia-abc1", "vpn-tunnel-pia",
		readyEndpoint("vpn-tunnel-pia-0", "10.2.0.1"),
		readyEndpoint("vpn-tunnel-pia-1", "10.2.0.2"),
	)
	cs := fake.NewSimpleClientset(slice)
	fc := newFleetController(map[string]int{"pia": 15})
	w := &sliceWatcher{cs: cs, namespace: testNamespace, fc: fc}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, done := w.startProvider(ctx, "vpn-tunnel-pia", "pia")
	defer stop()
	waitForInitialSync(t, done)

	waitForCondition(t, "initial healthy=2", func() bool {
		fc.mu.RLock()
		defer fc.mu.RUnlock()
		return fc.healthy["pia"] == 2
	})

	// Update: flip pod-0 to NotReady.
	updated := slice.DeepCopy()
	updated.Endpoints[0].Conditions.Ready = boolPtr(false)
	_, err := cs.DiscoveryV1().EndpointSlices(testNamespace).Update(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Update EndpointSlice: %v", err)
	}

	waitForCondition(t, "healthy drops to 1", func() bool {
		fc.mu.RLock()
		defer fc.mu.RUnlock()
		return fc.healthy["pia"] == 1
	})

	fc.mu.RLock()
	_, hasPod0 := fc.podToService["vpn-tunnel-pia-0"]
	fc.mu.RUnlock()
	if hasPod0 {
		t.Error("vpn-tunnel-pia-0 went NotReady but is still in podToService")
	}
}

func TestStartProvider_EmptySlicesStillSignalsReady(t *testing.T) {
	// No EndpointSlices for this provider — initial sync must still
	// complete (Service may legitimately have zero ready endpoints).
	cs := fake.NewSimpleClientset()
	fc := newFleetController(map[string]int{"surfshark": 15})
	w := &sliceWatcher{cs: cs, namespace: testNamespace, fc: fc}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, done := w.startProvider(ctx, "vpn-tunnel-surfshark", "surfshark")
	defer stop()
	waitForInitialSync(t, done)

	fc.mu.RLock()
	h := fc.healthy["surfshark"]
	fc.mu.RUnlock()
	if h != 0 {
		t.Errorf("healthy=%d, want 0 for empty-Service case", h)
	}
}
