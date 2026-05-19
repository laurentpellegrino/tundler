package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

// RotateTrigger runs one rotation cycle in the background. The /rotate
// handler invokes it in a goroutine so the HTTP request returns 202
// quickly while rotation completes asynchronously.
//
// Production wires this to rotateIfReady (which guards on state==Ready
// and is idempotent if the rotator timer fires concurrently). Tests pass
// a stub that records invocations.
type RotateTrigger func()

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
func startServer(ctx context.Context, state *StateTracker, triggerRotation RotateTrigger) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", livezHandler(state))
	mux.HandleFunc("/readyz", readyzHandler(state))
	mux.HandleFunc("/status", statusHandler(state))
	mux.HandleFunc("/rotate", rotateHandler(state, triggerRotation))

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

// rotateHandler implements POST /rotate. Called by tundler-fleet-controller
// (forwarding crawler- or operator-initiated rotations via per-pod DNS to
// pod:4242/rotate). Response shapes follow the design-doc "Response
// contract (RFC 9457 Problem Details for errors)" section.
//
//	state==Ready                → 202 Accepted (rotation runs async)
//	state==Draining/Rotating    → 200 OK (idempotent: already in progress)
//	state==Failed               → 409 Conflict, application/problem+json
//	state==Booting/LoggingIn/Connecting → 409 Conflict, problem-details
//	method != POST              → 405 Method Not Allowed
func rotateHandler(state *StateTracker, trigger RotateTrigger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		snap := state.Snapshot()
		switch snap.State {
		case StateReady:
			go trigger()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"state":            string(StateRotating),
				"previous_exit_ip": snap.CurrentExitIP,
			})
		case StateDraining, StateRotating:
			// Idempotent dedup: the design says "Already rotating /
			// draining → 200 OK" because the caller's intent (please
			// rotate this tunnel) is already being satisfied.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"state":   string(snap.State),
				"message": "rotation already in progress",
			})
		case StateFailed:
			writeProblem(w, problemDetails{
				Type:   "https://tundler-fleet-controller/errors/pod-failed-awaiting-restart",
				Title:  "Pod is in Failed state",
				Status: http.StatusConflict,
				Detail: "the pod is awaiting k8s restart; rotation cannot proceed",
			})
		default: // Booting, LoggingIn, Connecting
			writeProblem(w, problemDetails{
				Type:   "https://tundler-fleet-controller/errors/not-yet-ready",
				Title:  "Pod is not yet Ready to rotate",
				Status: http.StatusConflict,
				Detail: fmt.Sprintf("current state: %s", snap.State),
			})
		}
	}
}

// problemDetails is the RFC 9457 "Problem Details for HTTP APIs" shape.
// type is the stable machine-readable error code (clients dispatch on
// it, not on status code or title). status mirrors the HTTP status code
// for clients that want a single source.
type problemDetails struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func writeProblem(w http.ResponseWriter, p problemDetails) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}
