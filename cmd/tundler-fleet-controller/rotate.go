package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// problemTypeBase is the stable namespace for RFC 9457 problem-type URIs
// emitted by the fleet-controller. Each error sub-path is the
// machine-readable code clients dispatch on; the URI doesn't have to
// resolve to a real page.
//
// The crawler (Spring WebClient) dispatches on this `type` string, not
// on the HTTP status code (too coarse) or `title` (free text). Don't
// change these without bumping the crawler's dispatch table.
const problemTypeBase = "https://tundler-fleet-controller/errors"

// Problem-type URIs for the errors the fleet-controller generates
// itself. Pod-level errors (`pod-failed-awaiting-restart`,
// `rotation-exhausted-retries`) are passed through verbatim from the
// tundler-tunnel's /rotate response, so they aren't constants here.
const (
	problemTypeBadRequest      = problemTypeBase + "/bad-request"
	problemTypeUnknownTunnelID = problemTypeBase + "/unknown-tunnel-id"
	problemTypePodUnreachable  = problemTypeBase + "/pod-unreachable"
)

// problemDetails is the RFC 9457 response body. Encoded with
// Content-Type: application/problem+json — see writeProblem.
type problemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	TunnelID string `json:"tunnel_id,omitempty"`
}

func writeProblem(w http.ResponseWriter, p problemDetails) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// rotateForwarder isolates the side-effecting HTTP-to-tunnel-pod call
// so unit tests can substitute a stub without spinning up real HTTP
// servers per-tunnel-id. forwardRotate composes the stable per-pod
// DNS hostname (`<tunnel_id>.<svc>.<ns>.svc:4242`) and does the POST.
type rotateForwarder interface {
	forwardRotate(ctx context.Context, tunnelID, service string) (*http.Response, error)
}

// httpRotateForwarder is the production implementation. Uses a single
// http.Client with a sensible per-call timeout to bound how long the
// fleet-controller will block waiting for the pod's /rotate handler
// (which itself only initiates the rotation — it returns 202 well
// before drain+reconnect completes).
type httpRotateForwarder struct {
	namespace string
	client    *http.Client
}

func newHTTPRotateForwarder(namespace string) *httpRotateForwarder {
	return &httpRotateForwarder{
		namespace: namespace,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (h *httpRotateForwarder) forwardRotate(ctx context.Context, tunnelID, service string) (*http.Response, error) {
	url := fmt.Sprintf("http://%s.%s.%s.svc:4242/rotate", tunnelID, service, h.namespace)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return h.client.Do(req)
}

// rotateHandler holds the dependencies used by handleRotate. Constructed
// once at boot and registered on the mux.
type rotateHandler struct {
	fc        *FleetController
	forwarder rotateForwarder
}

// handleRotate is the /rotate handler. End-to-end:
//  1. Decode JSON body → tunnel_id
//  2. Look up the governing Service for that tunnel_id in the
//     EndpointSlices cache; reject as 400 if unknown.
//  3. Forward POST to the pod's stable per-pod DNS name on :4242.
//  4. Map transport-level errors to 502 (pod unreachable).
//  5. On success: propagate the pod's status + body verbatim.
//
// Why per-pod DNS (not a load-balanced Service): rotation MUST hit
// exactly the pod the crawler identified; per-pod DNS is the standard
// k8s mechanism for that, with coredns handling the IP resolution so
// pod restarts that change the IP are invisible at this layer.
func (h *rotateHandler) handleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, problemDetails{
			Type:   problemTypeBadRequest,
			Title:  "Method not allowed",
			Status: http.StatusMethodNotAllowed,
			Detail: "use POST",
		})
		return
	}
	var body struct {
		TunnelID string `json:"tunnel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProblem(w, problemDetails{
			Type:   problemTypeBadRequest,
			Title:  "Malformed request body",
			Status: http.StatusBadRequest,
			Detail: "POST body must be JSON with non-empty tunnel_id",
		})
		return
	}
	tid := strings.TrimSpace(body.TunnelID)
	if tid == "" {
		writeProblem(w, problemDetails{
			Type:   problemTypeBadRequest,
			Title:  "Missing tunnel_id",
			Status: http.StatusBadRequest,
			Detail: "POST body must contain non-empty tunnel_id",
		})
		return
	}

	service, ok := h.fc.serviceForTunnelID(tid)
	if !ok {
		writeProblem(w, problemDetails{
			Type:     problemTypeUnknownTunnelID,
			Title:    "Unknown tunnel_id",
			Status:   http.StatusBadRequest,
			Detail:   "tunnel_id is not in the current EndpointSlice cache",
			TunnelID: tid,
		})
		return
	}

	resp, err := h.forwarder.forwardRotate(r.Context(), tid, service)
	if err != nil {
		writeProblem(w, problemDetails{
			Type:     problemTypePodUnreachable,
			Title:    "Could not reach tunnel pod",
			Status:   http.StatusBadGateway,
			Detail:   err.Error(),
			TunnelID: tid,
		})
		return
	}
	defer resp.Body.Close()

	// Propagate the pod's response verbatim. The pod returns
	// application/json on success (202 / 200) and application/problem+json
	// for its own error states (409 Failed, 503 retries exhausted). Both
	// are valid passthrough — the crawler dispatches on `type` regardless.
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("rotate: copy pod response: %v", err)
	}
}

