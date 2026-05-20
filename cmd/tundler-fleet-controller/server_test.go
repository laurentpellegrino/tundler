package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, configured map[string]int) (*httpServer, *httptest.Server) {
	t.Helper()
	fc := newFleetController(configured)
	s := newHTTPServer(fc)
	mux := http.NewServeMux()
	s.register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return s, ts
}

func TestLivez_ReturnsOK(t *testing.T) {
	_, ts := newTestServer(t, map[string]int{"a": 1})
	resp, err := http.Get(ts.URL + "/livez")
	if err != nil {
		t.Fatalf("GET /livez: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d, want 200", resp.StatusCode)
	}
}

func TestReadyz_503BeforeMarkReady(t *testing.T) {
	_, ts := newTestServer(t, map[string]int{"a": 1})
	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "not yet warm") {
		t.Errorf("body=%q, want it to mention 'not yet warm'", string(body))
	}
}

func TestReadyz_200AfterMarkReady(t *testing.T) {
	s, ts := newTestServer(t, map[string]int{"a": 1})
	s.markReady()
	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d, want 200", resp.StatusCode)
	}
}

func TestStatus_ReturnsJSONPayload(t *testing.T) {
	s, ts := newTestServer(t, map[string]int{
		"expressvpn": 7,
		"nordvpn":    9,
	})
	s.fc.healthy["expressvpn"] = 5
	s.fc.healthy["nordvpn"] = 9

	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q, want application/json", got)
	}
	var payload statusPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if payload.TotalConfigured != 16 {
		t.Errorf("total_configured=%d, want 16", payload.TotalConfigured)
	}
	if payload.TotalHealthy != 14 {
		t.Errorf("total_healthy=%d, want 14", payload.TotalHealthy)
	}
	if payload.Providers["expressvpn"].Healthy != 5 {
		t.Errorf("expressvpn.healthy=%d, want 5", payload.Providers["expressvpn"].Healthy)
	}
}
