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

// livezHandler answers the kubelet liveness probe. Liveness is "is
// this process responsive?" — the act of serving this 200 IS the
// liveness signal kubelet wants. We deliberately do NOT inspect VPN
// state here: a rotation in progress, a brief Failed window, or even
// a stuck VPN daemon are not reasons to have kubelet recreate the
// CONTAINER (which wipes /var/log/journal and starts the kubelet
// restart counter ticking). Instead, runWedgeGuard (in main.go) calls
// os.Exit(1) when state stays not-Ready continuously past its
// threshold; systemd's Restart=always then respawns the binary inside
// the same container, preserving forensic logs and not touching the
// kubelet-visible restart count.
//
// /readyz remains the right probe for "should this pod be in the LB
// pool right now?" — see readyzHandler below. The hub envoy's
// ConsecutiveGatewayFailure outlier detection (xds_snapshot.go) is
// the second line of defense for steering traffic away from a
// transiently bad pod.
func livezHandler(state *StateTracker) http.HandlerFunc {
	_ = state // reserved for future structured liveness checks
	return func(w http.ResponseWriter, _ *http.Request) {
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

// minTimeBetweenRotations caps how rapidly the /rotate endpoint will
// trigger fresh rotations. The crawler's per-tunnel 429 tracking can
// fan out a burst of /rotate POSTs against the same pod when an exit
// IP gets banned by a downstream WAF: each new IP that also fails
// triggers another /rotate, and rotation-on-rotation overlaps were
// the dominant cause of pod thrash before this guard. After a
// rotation completes, we refuse to start another for this long, so
// the new exit IP gets at least one usable window before getting
// rotated away.
//
// Tuned conservatively: short enough that genuine "this IP is also
// banned" cases recover in well under a minute end-to-end (one
// debounce window plus one rotation), long enough that
// near-simultaneous burst /rotate calls from multiple slots get
// collapsed into a single rotation.
const minTimeBetweenRotations = 30 * time.Second

// rotateHandler implements POST /rotate. Called by tundler-fleet-controller
// (forwarding crawler- or operator-initiated rotations via per-pod DNS to
// pod:4242/rotate). Response shapes follow the design-doc "Response
// contract (RFC 9457 Problem Details for errors)" section.
//
//	state==Ready, debounced     → 200 OK (no-op, last rotation too recent)
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
			if since, recent := timeSinceLastRotation(snap); recent {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"state":   string(StateReady),
					"message": fmt.Sprintf("rotation debounced (last completed %s ago, min %s)",
						since.Round(time.Second), minTimeBetweenRotations),
				})
				return
			}
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

// timeSinceLastRotation reports how long ago the last rotation
// completed and whether that's within the debounce window. Returns
// (0, false) when there's no prior rotation or the timestamp can't
// be parsed (defensive — never block /rotate on a malformed snapshot).
func timeSinceLastRotation(snap Snapshot) (time.Duration, bool) {
	if snap.LastRotation == nil || snap.LastRotation.CompletedAt == "" {
		return 0, false
	}
	completed, err := time.Parse(time.RFC3339, snap.LastRotation.CompletedAt)
	if err != nil {
		return 0, false
	}
	since := time.Since(completed)
	return since, since < minTimeBetweenRotations
}
