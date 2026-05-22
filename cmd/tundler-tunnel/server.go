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

// StateMaxNonReady caps how long /livez tolerates the pod being out of
// StateReady before reporting unhealthy. Transient transitions
// (Draining→Rotating→Connecting→Ready) and even a brief Failed state
// (after which the rotator will retry on the next periodic tick) stay
// well under this window. A pod that has been wedged out of Ready for
// longer than this almost certainly needs a k8s restart — either the
// VPN account is throttled long enough that retry isn't getting us
// anywhere, or the process is deadlocked. Tuned so a slow ExpressVPN
// Lightway reconnect (30 s × 3 attempts ≈ 100 s worst case) plus the
// envoy-drain phase still fit comfortably below the threshold.
const StateMaxNonReady = 5 * time.Minute

// livezHandler is intentionally lenient. The k8s liveness contract is
// "should this process be restarted?" — NOT "is this pod ready to
// serve?" (that's /readyz). So /livez stays 200 across all transient
// non-Ready states: Booting, LoggingIn, Connecting, Draining, Rotating,
// and even Failed (the rotator retries from Failed on its next tick).
// The single trigger for a 503 is "non-Ready for too long" — set by
// StateMaxNonReady. That catches genuine wedges (deadlock, exhausted
// retries, account banned) while letting normal-but-slow rotations
// complete without kubelet killing a working pod.
//
// Special case: a pod that has NEVER been Ready (lastReadyAt zero)
// gets the full StateMaxNonReady from process start before we'd report
// unhealthy. That accommodates the initial-login flow (which can take
// 30-90 s with ExpressVPN) without flapping right after boot.
func livezHandler(state *StateTracker) http.HandlerFunc {
	processStart := time.Now()
	return func(w http.ResponseWriter, _ *http.Request) {
		if state.Get() == StateReady {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Determine the reference point we're measuring "stuck" from.
		// Before the first Ready, that's process start; after, it's
		// the most recent transition into Ready.
		ref := state.LastReadyAt()
		if ref.IsZero() {
			ref = processStart
		}
		if time.Since(ref) > StateMaxNonReady {
			http.Error(w, fmt.Sprintf("non-Ready for %s (> %s); restart requested",
				time.Since(ref).Round(time.Second), StateMaxNonReady),
				http.StatusServiceUnavailable)
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
