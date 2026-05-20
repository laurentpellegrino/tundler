package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// stubForwarder is the test substitute for httpRotateForwarder. Each
// call records the (tunnelID, service) pair and returns whatever the
// test pre-programmed via setNextResponse / setNextError.
type stubForwarder struct {
	calls atomic.Int32

	// Programmed outcome (set via setNextResponse OR setNextError).
	nextStatus      int
	nextContentType string
	nextBody        string
	nextErr         error

	// Captured request — read by the test after the handler runs.
	gotTunnelID string
	gotService  string
}

func (s *stubForwarder) setOK(status int, body string) {
	s.nextStatus = status
	s.nextContentType = "application/json"
	s.nextBody = body
	s.nextErr = nil
}
func (s *stubForwarder) setProblem(status int, body string) {
	s.nextStatus = status
	s.nextContentType = "application/problem+json"
	s.nextBody = body
	s.nextErr = nil
}
func (s *stubForwarder) setError(err error) {
	s.nextErr = err
}

func (s *stubForwarder) forwardRotate(_ context.Context, tunnelID, service string) (*http.Response, error) {
	s.calls.Add(1)
	s.gotTunnelID = tunnelID
	s.gotService = service
	if s.nextErr != nil {
		return nil, s.nextErr
	}
	resp := &http.Response{
		StatusCode: s.nextStatus,
		Body:       io.NopCloser(strings.NewReader(s.nextBody)),
		Header:     http.Header{},
	}
	if s.nextContentType != "" {
		resp.Header.Set("Content-Type", s.nextContentType)
	}
	return resp, nil
}

func newRotateTestServer(t *testing.T, configured map[string]int, pods map[string]string) (*httptest.Server, *stubForwarder) {
	t.Helper()
	fc := newFleetController(configured)
	for podName, svc := range pods {
		fc.podToService[podName] = svc
	}
	srv := newHTTPServer(fc)
	mux := http.NewServeMux()
	srv.register(mux)
	fwd := &stubForwarder{}
	srv.registerRotate(mux, fwd)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, fwd
}

func postJSON(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func decodeProblem(t *testing.T, resp *http.Response) problemDetails {
	t.Helper()
	if got := resp.Header.Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type=%q, want application/problem+json", got)
	}
	var p problemDetails
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	return p
}

func TestRotate_MalformedBody_BadRequest(t *testing.T) {
	ts, fwd := newRotateTestServer(t,
		map[string]int{"expressvpn": 7},
		map[string]string{"vpn-tunnel-expressvpn-0": "vpn-tunnel-expressvpn"},
	)
	resp := postJSON(t, ts.URL+"/rotate", "}{ not json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", resp.StatusCode)
	}
	p := decodeProblem(t, resp)
	if p.Type != problemTypeBadRequest {
		t.Errorf("type=%q, want %q", p.Type, problemTypeBadRequest)
	}
	if fwd.calls.Load() != 0 {
		t.Errorf("forwarder called %d times, want 0", fwd.calls.Load())
	}
}

func TestRotate_MissingTunnelID_BadRequest(t *testing.T) {
	ts, fwd := newRotateTestServer(t, map[string]int{"a": 1}, nil)
	resp := postJSON(t, ts.URL+"/rotate", `{"tunnel_id": ""}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", resp.StatusCode)
	}
	p := decodeProblem(t, resp)
	if p.Type != problemTypeBadRequest {
		t.Errorf("type=%q, want %q", p.Type, problemTypeBadRequest)
	}
	if fwd.calls.Load() != 0 {
		t.Errorf("forwarder called %d times, want 0", fwd.calls.Load())
	}
}

func TestRotate_UnknownTunnelID_BadRequest(t *testing.T) {
	ts, fwd := newRotateTestServer(t,
		map[string]int{"expressvpn": 7},
		map[string]string{"vpn-tunnel-expressvpn-0": "vpn-tunnel-expressvpn"},
	)
	resp := postJSON(t, ts.URL+"/rotate", `{"tunnel_id": "vpn-tunnel-foo-99"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", resp.StatusCode)
	}
	p := decodeProblem(t, resp)
	if p.Type != problemTypeUnknownTunnelID {
		t.Errorf("type=%q, want %q", p.Type, problemTypeUnknownTunnelID)
	}
	if p.TunnelID != "vpn-tunnel-foo-99" {
		t.Errorf("p.tunnel_id=%q, want vpn-tunnel-foo-99", p.TunnelID)
	}
	if fwd.calls.Load() != 0 {
		t.Errorf("forwarder called %d times, want 0", fwd.calls.Load())
	}
}

func TestRotate_PodUnreachable_BadGateway(t *testing.T) {
	ts, fwd := newRotateTestServer(t,
		map[string]int{"expressvpn": 7},
		map[string]string{"vpn-tunnel-expressvpn-3": "vpn-tunnel-expressvpn"},
	)
	fwd.setError(errors.New("dial tcp: lookup ... no such host"))

	resp := postJSON(t, ts.URL+"/rotate", `{"tunnel_id": "vpn-tunnel-expressvpn-3"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status=%d, want 502", resp.StatusCode)
	}
	p := decodeProblem(t, resp)
	if p.Type != problemTypePodUnreachable {
		t.Errorf("type=%q, want %q", p.Type, problemTypePodUnreachable)
	}
	if !strings.Contains(p.Detail, "no such host") {
		t.Errorf("p.detail=%q, want it to mention 'no such host'", p.Detail)
	}
	if got := fwd.gotTunnelID; got != "vpn-tunnel-expressvpn-3" {
		t.Errorf("forwarder got tunnelID=%q, want vpn-tunnel-expressvpn-3", got)
	}
	if got := fwd.gotService; got != "vpn-tunnel-expressvpn" {
		t.Errorf("forwarder got service=%q, want vpn-tunnel-expressvpn", got)
	}
}

func TestRotate_PropagatesPodSuccess_202(t *testing.T) {
	ts, fwd := newRotateTestServer(t,
		map[string]int{"expressvpn": 7},
		map[string]string{"vpn-tunnel-expressvpn-3": "vpn-tunnel-expressvpn"},
	)
	podBody := `{"tunnel_id":"vpn-tunnel-expressvpn-3","previous_exit_ip":"45.83.124.18","state":"Rotating"}`
	fwd.setOK(http.StatusAccepted, podBody)

	resp := postJSON(t, ts.URL+"/rotate", `{"tunnel_id": "vpn-tunnel-expressvpn-3"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status=%d, want 202 (pod's 202 passed through)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q, want application/json (passthrough)", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, []byte(podBody)) {
		t.Errorf("body mismatch:\n got=%s\nwant=%s", body, podBody)
	}
}

func TestRotate_PropagatesPodProblem_409(t *testing.T) {
	// Pod is in Failed state — emits its own RFC 9457 problem. Fleet-
	// controller MUST passthrough the status code, content-type, and
	// body unchanged (so the crawler's dispatch table sees the pod's
	// `type` URI directly, not a fleet-controller wrapping).
	ts, fwd := newRotateTestServer(t,
		map[string]int{"expressvpn": 7},
		map[string]string{"vpn-tunnel-expressvpn-5": "vpn-tunnel-expressvpn"},
	)
	podProblem := `{"type":"https://tundler-tunnel/errors/pod-failed-awaiting-restart","title":"Pod is in Failed state","status":409,"tunnel_id":"vpn-tunnel-expressvpn-5"}`
	fwd.setProblem(http.StatusConflict, podProblem)

	resp := postJSON(t, ts.URL+"/rotate", `{"tunnel_id": "vpn-tunnel-expressvpn-5"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status=%d, want 409 (pod's 409 passed through)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type=%q, want application/problem+json (passthrough)", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, []byte(podProblem)) {
		t.Errorf("body mismatch:\n got=%s\nwant=%s", body, podProblem)
	}
}

func TestRotate_MethodNotAllowed_405(t *testing.T) {
	ts, fwd := newRotateTestServer(t, map[string]int{"a": 1}, nil)
	resp, err := http.Get(ts.URL + "/rotate")
	if err != nil {
		t.Fatalf("GET /rotate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status=%d, want 405", resp.StatusCode)
	}
	if fwd.calls.Load() != 0 {
		t.Errorf("forwarder called %d times, want 0", fwd.calls.Load())
	}
}

// TestHTTPRotateForwarder_BuildsExpectedURL is a tiny sanity check on
// the production forwarder's URL composition. We can't actually POST
// to it (the hostname won't resolve) but we can intercept via a custom
// Transport.
func TestHTTPRotateForwarder_BuildsExpectedURL(t *testing.T) {
	captured := make(chan string, 1)
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		captured <- req.URL.String()
		return &http.Response{
			StatusCode: 202,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     http.Header{},
		}, nil
	})
	fwd := &httpRotateForwarder{
		namespace: "ipregistry-production",
		client:    &http.Client{Transport: rt},
	}
	_, err := fwd.forwardRotate(context.Background(),
		"vpn-tunnel-expressvpn-3", "vpn-tunnel-expressvpn")
	if err != nil {
		t.Fatalf("forwardRotate: %v", err)
	}
	got := <-captured
	want := "http://vpn-tunnel-expressvpn-3.vpn-tunnel-expressvpn.ipregistry-production.svc:4242/rotate"
	if got != want {
		t.Errorf("URL=%s, want %s", got, want)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
