package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync/atomic"
)

// httpServer wraps a *FleetController with the readyz gate and serves
// the four crawler-facing endpoints (/livez, /readyz, /status, /rotate).
//
// Readyz semantics (from the design doc):
//   /readyz returns 200 ONLY after every per-provider EndpointSlice
//   informer has received its initial reconcile event. Until then,
//   kube-proxy excludes this Pod from the tundler-fleet-controller
//   Service backends and crawlers route to one of the other 2 replicas.
//   This eliminates the cold-start window where /rotate could falsely
//   reject a valid tunnel_id as "unknown" (cache not populated yet).
type httpServer struct {
	fc    *FleetController
	ready atomic.Bool
}

func newHTTPServer(fc *FleetController) *httpServer {
	return &httpServer{fc: fc}
}

// markReady flips /readyz to 200. Called by the informer warm-up code
// once every per-provider initial-reconcile has completed (Slice 2 wires
// this from a sync.WaitGroup).
func (s *httpServer) markReady() {
	s.ready.Store(true)
}

// register attaches handlers to a mux. Kept separate from ListenAndServe
// so tests can call register on a fresh mux and exercise handlers via
// httptest.NewServer without binding a real port.
func (s *httpServer) register(mux *http.ServeMux) {
	mux.HandleFunc("/livez", s.handleLivez)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/status", s.handleStatus)
}

func (s *httpServer) handleLivez(w http.ResponseWriter, _ *http.Request) {
	// Liveness = the process is up. Cache-warm state lives behind /readyz.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *httpServer) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		http.Error(w, "informer caches not yet warm\n", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *httpServer) handleStatus(w http.ResponseWriter, _ *http.Request) {
	payload := s.fc.statusSnapshot()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("encode /status: %v", err)
	}
}
