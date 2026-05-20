// Command tundler-fleet-controller is the sidecar process that runs in
// the same Pod as the global hub envoy. It maintains a k8s
// EndpointSlices-driven view of the per-provider tunnel-pod fleet, pushes
// CDS+EDS snapshots to the pod-local envoy over loopback xDS, and exposes
// /status + /rotate to the crawler.
//
// See docs/architecture-tundler-fleet-controller.md for the full design.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// vpnProvidersPath is where the vpn-providers ConfigMap is mounted in
	// the fleet-controller container (see Deployment manifest in the
	// design doc). The fsnotify watcher (Slice 4) tracks this path.
	defaultVPNProvidersPath = "/etc/vpn-providers/vpn-providers.yaml"

	// httpAddr is the crawler-facing HTTP port (/status, /rotate, /livez,
	// /readyz). Exposed via the tundler-fleet-controller Service.
	httpAddr = ":9090"

	// resyncPeriod is how often the EndpointSlices informers do a full
	// re-list against the apiserver as a safety net against missed
	// watch events. 30s matches the design-doc snippet.
	resyncPeriod = 30 * time.Second
)

func main() {
	path := os.Getenv("VPN_PROVIDERS_PATH")
	if path == "" {
		path = defaultVPNProvidersPath
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		log.Fatal("POD_NAMESPACE not set — required to scope the EndpointSlices watch")
	}

	configured, err := loadConfigured(path)
	if err != nil {
		log.Fatalf("load vpn-providers: %v", err)
	}
	log.Printf("loaded vpn-providers.yaml: %d providers configured", len(configured))

	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("in-cluster k8s config: %v", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("kubernetes clientset: %v", err)
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	fc := newFleetController(configured)
	srv := newHTTPServer(fc)
	mux := http.NewServeMux()
	srv.register(mux)
	srv.registerRotate(mux, newHTTPRotateForwarder(namespace))

	xdsSrv := newFleetXDSServer(fc)
	// Seed an initial snapshot so the hub envoy gets clusters as soon as
	// it connects — even if no EndpointSlices have arrived yet, envoy
	// learns the cluster list (with empty endpoint sets) and is ready to
	// pick up endpoints the moment the first reconcile lands.
	if err := xdsSrv.rebuildSnapshot(); err != nil {
		log.Fatalf("initial xds snapshot: %v", err)
	}
	go func() {
		if err := xdsSrv.Serve(ctx, fleetXDSAddr); err != nil {
			log.Printf("xds server: %v", err)
		}
	}()

	watcher := &sliceWatcher{
		cs:           cs,
		namespace:    namespace,
		fc:           fc,
		resyncPeriod: resyncPeriod,
		onReconcile: func() {
			if err := xdsSrv.rebuildSnapshot(); err != nil {
				log.Printf("rebuild snapshot after reconcile: %v", err)
			}
		},
	}

	cfgWatcher := &configWatcher{
		path: path,
		onReload: func(next map[string]int) {
			log.Printf("vpn-providers.yaml reloaded: %d providers configured", len(next))
			fc.replaceConfigured(next)
			if err := xdsSrv.rebuildSnapshot(); err != nil {
				log.Printf("rebuild snapshot after config reload: %v", err)
			}
		},
	}
	go func() {
		if err := cfgWatcher.watchConfig(ctx); err != nil {
			log.Printf("config watch: %v", err)
		}
	}()

	// Boot one informer per configured provider; gate /readyz on every
	// initial reconcile completing. Until that's done kube-proxy holds
	// this Pod out of the Service backends and crawlers route to the
	// other 2 hub Pods.
	var wg sync.WaitGroup
	stops := make([]func(), 0, len(configured))
	for provider := range configured {
		svcName := "tundler-tunnel-" + provider
		stop, done := watcher.startProvider(ctx, svcName, provider)
		stops = append(stops, stop)
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			select {
			case <-done:
				log.Printf("informer warm: provider=%s", p)
			case <-ctx.Done():
			}
		}(provider)
	}

	go func() {
		wg.Wait()
		select {
		case <-ctx.Done():
			return
		default:
		}
		srv.markReady()
		log.Printf("all informers warm; /readyz now returns 200")
	}()

	httpSrv := &http.Server{Addr: httpAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		log.Printf("shutdown signal received; closing HTTP server + informers")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		for _, stop := range stops {
			stop()
		}
	}()

	log.Printf("tundler-fleet-controller listening on %s", httpAddr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http server: %v", err)
	}
}
