package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"
)

// httpListenAddr is the bind address for tundler-tunnel's control-plane API
// (consumed by k8s probes, by the in-pod operator via `kubectl exec curl`,
// and by tundler-fleet-controller's per-pod-DNS rotation forwarder).
//
// 0.0.0.0 (not loopback) because the headless governing Service routes
// pod-IP traffic here for /rotate, and httpGet probes target the pod IP.
// xDS gRPC :18000 is the loopback-only port (different concern).
const httpListenAddr = "0.0.0.0:4242"

// startServer wires the HTTP handlers and starts listening. Returns when
// ctx is cancelled or the server hits an error. Server lifecycle is the
// caller's responsibility — main passes its own context.
func startServer(ctx context.Context, state *StateTracker) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", livezHandler(state))
	mux.HandleFunc("/readyz", readyzHandler(state))
	mux.HandleFunc("/status", statusHandler(state))

	srv := &http.Server{
		Addr:              httpListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("tundler-tunnel: HTTP API listening on %s", httpListenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// livezHandler returns 200 unless the pod has surrendered to Failed (per
// the design-doc "readiness vs liveness" distinction in failed-rotation
// handling: /livez stays 200 as long as the process is alive AND hasn't
// surrendered — Failed means k8s should restart the pod).
func livezHandler(state *StateTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if state.Get() == StateFailed {
			http.Error(w, "Failed: awaiting k8s restart", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// readyzHandler returns 200 only when the pod is genuinely ready to serve
// traffic — currently means state==Ready (logged in). Future slices will
// also gate on tunnel-up; when rotation lands, /readyz flips to 503 the
// instant tundler-tunnel decides to rotate (Draining), and stays 503 until
// rotation succeeds or surrenders.
func readyzHandler(state *StateTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		s := state.Get()
		if s != StateReady {
			http.Error(w, "not ready: state="+string(s), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// statusHandler returns the JSON snapshot per the
// "Tundler-hub /status response schema" section of the design doc.
func statusHandler(state *StateTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state.Snapshot())
	}
}
