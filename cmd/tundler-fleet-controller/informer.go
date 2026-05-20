package main

import (
	"context"
	"log"
	"sync"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// sliceWatcher wires per-provider EndpointSlices SharedInformers to the
// FleetController's in-memory cache. One sliceWatcher per fleet-controller
// process; it starts one informer per configured provider Service.
//
// Why SharedInformer (not a raw Watch loop): SharedInformer handles
// watch-close relists, etcd compaction (HTTP 410 Gone), apiserver
// restarts, and resync intervals. A naive for { Watch } loop silently
// drops events between watch close and reconnect, which would let the
// fleet-controller's cache drift from k8s reality undetected.
type sliceWatcher struct {
	cs        kubernetes.Interface
	namespace string
	fc        *FleetController

	// onReconcile fires after every successful reconcile (initial sync
	// AND every subsequent EndpointSlice event). Used in production to
	// rebuild the xDS snapshot; nil-safe.
	onReconcile func()

	// resyncPeriod controls the informer's full-list resync interval.
	// 30s in production; tests pass 0 (no periodic resync — they drive
	// events explicitly).
	resyncPeriod time.Duration
}

// startProvider boots one SharedInformer watching EndpointSlices labeled
// `kubernetes.io/service-name=<svcName>`. The returned stop function
// shuts the informer down. initialSyncDone is signaled (closed) once the
// informer's first List completes AND the first reconcile runs — at that
// point the cache is warm for this provider.
func (w *sliceWatcher) startProvider(ctx context.Context, svcName, provider string) (stop func(), initialSyncDone <-chan struct{}) {
	factory := informers.NewSharedInformerFactoryWithOptions(
		w.cs,
		w.resyncPeriod,
		informers.WithNamespace(w.namespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.LabelSelector = "kubernetes.io/service-name=" + svcName
		}),
	)
	lister := factory.Discovery().V1().EndpointSlices().Lister()
	inf := factory.Discovery().V1().EndpointSlices().Informer()

	done := make(chan struct{})
	var initOnce sync.Once
	signalReady := func() { initOnce.Do(func() { close(done) }) }

	reconcile := func() {
		// Reconcile from the indexed cache (always in sync with the
		// apiserver thanks to the informer's relist machinery), not
		// from the event payload — which only carries the diff.
		sel := labels.SelectorFromSet(labels.Set{"kubernetes.io/service-name": svcName})
		slices, err := lister.EndpointSlices(w.namespace).List(sel)
		if err != nil {
			log.Printf("list endpointslices for %s: %v", svcName, err)
			return
		}
		addrs := []string{}
		names := []string{}
		for _, s := range slices {
			for _, ep := range s.Endpoints {
				if ep.Conditions.Ready == nil || !*ep.Conditions.Ready {
					continue
				}
				if len(ep.Addresses) > 0 {
					addrs = append(addrs, ep.Addresses[0])
				}
				if ep.TargetRef != nil && ep.TargetRef.Name != "" {
					names = append(names, ep.TargetRef.Name)
				}
			}
		}
		w.fc.applyProviderReconcile(provider, svcName, addrs, names)
		if w.onReconcile != nil {
			w.onReconcile()
		}
		signalReady()
	}

	_, _ = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ interface{}) { reconcile() },
		UpdateFunc: func(_, _ interface{}) { reconcile() },
		DeleteFunc: func(_ interface{}) { reconcile() },
	})

	stopCh := make(chan struct{})
	var stopOnce sync.Once
	stop = func() { stopOnce.Do(func() { close(stopCh) }) }
	// Propagate ctx cancellation to the informer's stop channel.
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-stopCh:
		}
	}()
	factory.Start(stopCh)

	// WaitForCacheSync blocks until the initial List finishes. After
	// that, the informer's resync + watch loop drives reconciles via
	// the event handlers. We also run one reconcile inline here — the
	// AddFunc/UpdateFunc event handlers are only invoked for items that
	// exist; for a Service with zero endpoints, no event fires and we'd
	// never signalReady. Running once explicitly handles that case.
	go func() {
		if ok := cache.WaitForCacheSync(stopCh, inf.HasSynced); !ok {
			log.Printf("cache sync failed for %s — stopCh closed?", svcName)
			return
		}
		reconcile()
	}()

	return stop, done
}

// applyProviderReconcile is the FleetController-side mutator for one
// provider's reconcile. Defined as a method so callers don't open-code
// the mu.Lock dance.
func (f *FleetController) applyProviderReconcile(provider, svcName string, addrs, names []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Rebuild the podToService entries that came from THIS svc — pods
	// that were ready last reconcile but aren't any more drop out.
	for podName, svc := range f.podToService {
		if svc == svcName {
			delete(f.podToService, podName)
		}
	}
	for _, name := range names {
		f.podToService[name] = svcName
	}
	f.healthy[provider] = len(addrs)
	cpAddrs := make([]string, len(addrs))
	copy(cpAddrs, addrs)
	f.podAddrs[provider] = cpAddrs
}

// Compile-time check that *discoveryv1.EndpointSlice is what the
// informer factory hands us — keeps the import alive if reconcile() ever
// regresses to a typed accessor.
var _ = (*discoveryv1.EndpointSlice)(nil)
