// Command tundler-fleet-controller is the sidecar process that runs in
// the same Pod as the global hub envoy. It maintains a k8s
// EndpointSlices-driven view of the per-provider tunnel-pod fleet, pushes
// CDS+EDS snapshots to the pod-local envoy over loopback xDS, and exposes
// /status + /rotate to the crawler.
//
// See docs/architecture-tundler-fleet-controller.md for the full design.
package main

import (
	"log"
	"net/http"
	"os"
)

const (
	// vpnProvidersPath is where the vpn-providers ConfigMap is mounted in
	// the fleet-controller container (see Deployment manifest in the
	// design doc). The fsnotify watcher (Slice 4) tracks this path.
	defaultVPNProvidersPath = "/etc/vpn-providers/vpn-providers.yaml"

	// httpAddr is the crawler-facing HTTP port (/status, /rotate, /livez,
	// /readyz). Exposed via the tundler-fleet-controller Service.
	httpAddr = ":9090"
)

func main() {
	path := os.Getenv("VPN_PROVIDERS_PATH")
	if path == "" {
		path = defaultVPNProvidersPath
	}

	configured, err := loadConfigured(path)
	if err != nil {
		log.Fatalf("load vpn-providers: %v", err)
	}
	log.Printf("loaded vpn-providers.yaml: %d providers configured", len(configured))

	fc := newFleetController(configured)
	srv := newHTTPServer(fc)

	mux := http.NewServeMux()
	srv.register(mux)

	// TODO(slice-2): start EndpointSlices informers per provider, gate
	// markReady() on every initial reconcile completing. For now mark
	// ready immediately so /readyz returns 200 in single-binary smoke
	// tests of the skeleton.
	srv.markReady()

	log.Printf("tundler-fleet-controller listening on %s", httpAddr)
	if err := http.ListenAndServe(httpAddr, mux); err != nil {
		log.Fatalf("http server: %v", err)
	}
}
