package main

import (
	"context"
	"sort"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
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

// TestStartProvider_InitialSyncFromPrePopulatedSlices is the one
// end-to-end test for the SharedInformer wiring: it asserts that the
// informer hands the prepopulated EndpointSlices to reconcile() and
// that the resulting FleetController state matches what the slices
// describe (Ready endpoints become podAddrs, NotReady are dropped,
// podToService gets populated, healthy counter matches).
//
// Watch-driven update behavior (Add/Update/Delete events after the
// initial sync) is tested directly against applyProviderReconcile in
// the table-driven test below — the fake clientset's label-selector
// watch is flaky enough that exercising it would force the suite into
// multi-second polling deadlines without proving anything we don't
// already know about applyProviderReconcile.
func TestStartProvider_InitialSyncFromPrePopulatedSlices(t *testing.T) {
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

// TestApplyProviderReconcile covers the cache-mutation contract that
// the informer event handler relies on: each reconcile fully replaces
// this provider's entries in podAddrs / podToService / healthy, so pods
// that disappeared (Ready→NotReady, deleted, evicted) are dropped from
// the maps in the same operation that adds new ones. This is what
// matters for snapshot freshness; the SharedInformer's job is just to
// drive reconciles, which is well-tested upstream.
func TestApplyProviderReconcile_FullReplaceSemantics(t *testing.T) {
	fc := newFleetController(map[string]int{"expressvpn": 7})

	// First reconcile: two pods Ready.
	fc.applyProviderReconcile("expressvpn", "vpn-tunnel-expressvpn",
		[]string{"10.0.0.1", "10.0.0.2"},
		[]string{"vpn-tunnel-expressvpn-0", "vpn-tunnel-expressvpn-1"},
	)
	if got := fc.healthy["expressvpn"]; got != 2 {
		t.Errorf("after first reconcile: healthy=%d, want 2", got)
	}
	if _, ok := fc.podToService["vpn-tunnel-expressvpn-0"]; !ok {
		t.Error("podToService[vpn-tunnel-expressvpn-0] missing after first reconcile")
	}

	// Second reconcile: pod-0 went NotReady, pod-2 came up. The
	// reconcile is a full replace for this svc — pod-0 disappears from
	// podToService AND podAddrs.
	fc.applyProviderReconcile("expressvpn", "vpn-tunnel-expressvpn",
		[]string{"10.0.0.2", "10.0.0.3"},
		[]string{"vpn-tunnel-expressvpn-1", "vpn-tunnel-expressvpn-2"},
	)
	if got := fc.healthy["expressvpn"]; got != 2 {
		t.Errorf("after second reconcile: healthy=%d, want 2", got)
	}
	if _, ok := fc.podToService["vpn-tunnel-expressvpn-0"]; ok {
		t.Error("vpn-tunnel-expressvpn-0 should have been dropped on second reconcile")
	}
	if _, ok := fc.podToService["vpn-tunnel-expressvpn-2"]; !ok {
		t.Error("vpn-tunnel-expressvpn-2 should have been added on second reconcile")
	}
	sort.Strings(fc.podAddrs["expressvpn"])
	if want := []string{"10.0.0.2", "10.0.0.3"}; !equalSlices(fc.podAddrs["expressvpn"], want) {
		t.Errorf("podAddrs=%v, want %v", fc.podAddrs["expressvpn"], want)
	}
}

func TestApplyProviderReconcile_OneProviderDoesNotTouchAnother(t *testing.T) {
	fc := newFleetController(map[string]int{"expressvpn": 7, "nordvpn": 9})

	fc.applyProviderReconcile("expressvpn", "vpn-tunnel-expressvpn",
		[]string{"10.0.0.1"},
		[]string{"vpn-tunnel-expressvpn-0"},
	)
	fc.applyProviderReconcile("nordvpn", "vpn-tunnel-nordvpn",
		[]string{"10.1.0.1", "10.1.0.2"},
		[]string{"vpn-tunnel-nordvpn-0", "vpn-tunnel-nordvpn-1"},
	)

	// Re-reconcile expressvpn with a different set — nordvpn's view
	// must be untouched.
	fc.applyProviderReconcile("expressvpn", "vpn-tunnel-expressvpn",
		[]string{"10.0.0.5"},
		[]string{"vpn-tunnel-expressvpn-5"},
	)
	if fc.healthy["nordvpn"] != 2 {
		t.Errorf("nordvpn healthy=%d after expressvpn reconcile, want 2", fc.healthy["nordvpn"])
	}
	if _, ok := fc.podToService["vpn-tunnel-nordvpn-0"]; !ok {
		t.Error("nordvpn entry in podToService was incorrectly evicted by expressvpn reconcile")
	}
	if _, ok := fc.podToService["vpn-tunnel-expressvpn-0"]; ok {
		t.Error("stale expressvpn-0 should have been replaced by expressvpn-5")
	}
}

func TestApplyProviderReconcile_EmptyDropsAllPodsForProvider(t *testing.T) {
	fc := newFleetController(map[string]int{"expressvpn": 7})
	fc.applyProviderReconcile("expressvpn", "vpn-tunnel-expressvpn",
		[]string{"10.0.0.1", "10.0.0.2"},
		[]string{"vpn-tunnel-expressvpn-0", "vpn-tunnel-expressvpn-1"},
	)
	// All pods rotated out — every endpoint NotReady → reconcile with empty.
	fc.applyProviderReconcile("expressvpn", "vpn-tunnel-expressvpn", nil, nil)
	if got := fc.healthy["expressvpn"]; got != 0 {
		t.Errorf("healthy=%d after empty reconcile, want 0", got)
	}
	if got := len(fc.podAddrs["expressvpn"]); got != 0 {
		t.Errorf("podAddrs len=%d, want 0", got)
	}
	for podName := range fc.podToService {
		t.Errorf("podToService still has %q after empty reconcile", podName)
	}
}
