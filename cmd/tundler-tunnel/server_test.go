package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLivezHandler(t *testing.T) {
	cases := []struct {
		state State
		want  int
	}{
		{StateBooting, http.StatusOK},
		{StateLoggingIn, http.StatusOK},
		{StateReady, http.StatusOK},
		{StateFailed, http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		t.Run(string(c.state), func(t *testing.T) {
			st := NewStateTracker("expressvpn")
			st.Set(c.state)
			rr := httptest.NewRecorder()
			livezHandler(st)(rr, httptest.NewRequest(http.MethodGet, "/livez", nil))
			if rr.Code != c.want {
				t.Errorf("state=%s: /livez got %d, want %d", c.state, rr.Code, c.want)
			}
		})
	}
}

func TestReadyzHandler(t *testing.T) {
	cases := []struct {
		state State
		want  int
	}{
		{StateBooting, http.StatusServiceUnavailable},
		{StateLoggingIn, http.StatusServiceUnavailable},
		{StateReady, http.StatusOK},
		{StateFailed, http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		t.Run(string(c.state), func(t *testing.T) {
			st := NewStateTracker("expressvpn")
			st.Set(c.state)
			rr := httptest.NewRecorder()
			readyzHandler(st)(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rr.Code != c.want {
				t.Errorf("state=%s: /readyz got %d, want %d", c.state, rr.Code, c.want)
			}
		})
	}
}

func TestStatusHandler_BootingShape(t *testing.T) {
	st := NewStateTracker("expressvpn")
	st.RecordBootLoginJitter(47 * time.Second)

	rr := httptest.NewRecorder()
	statusHandler(st)(rr, httptest.NewRequest(http.MethodGet, "/status", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("/status got %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q, want application/json", ct)
	}

	var snap map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got := snap["state"]; got != "Booting" {
		t.Errorf("state=%v, want Booting", got)
	}
	if got := snap["provider"]; got != "expressvpn" {
		t.Errorf("provider=%v, want expressvpn", got)
	}
	if got := snap["boot_login_jitter_actual_seconds"]; got != float64(47) {
		t.Errorf("boot_login_jitter_actual_seconds=%v, want 47", got)
	}
	if _, present := snap["logged_in_at"]; present {
		t.Errorf("logged_in_at should be omitted when zero, got %v", snap["logged_in_at"])
	}
}

func TestStatusHandler_ReadyEmitsLoggedInAt(t *testing.T) {
	st := NewStateTracker("nordvpn")
	st.Set(StateReady)

	rr := httptest.NewRecorder()
	statusHandler(st)(rr, httptest.NewRequest(http.MethodGet, "/status", nil))

	var snap map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := snap["state"]; got != "Ready" {
		t.Errorf("state=%v, want Ready", got)
	}
	loggedInAt, ok := snap["logged_in_at"].(string)
	if !ok || loggedInAt == "" {
		t.Errorf("logged_in_at should be set on Ready transition, got %v", snap["logged_in_at"])
	}
	if _, err := time.Parse(time.RFC3339, loggedInAt); err != nil {
		t.Errorf("logged_in_at=%q is not RFC3339: %v", loggedInAt, err)
	}
}

func TestStatusHandler_TunnelUpFields(t *testing.T) {
	st := NewStateTracker("expressvpn")
	st.RecordTunnelUp("Switzerland", "45.83.124.18")
	st.Set(StateReady)

	rr := httptest.NewRecorder()
	statusHandler(st)(rr, httptest.NewRequest(http.MethodGet, "/status", nil))

	var snap map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := snap["current_location"]; got != "Switzerland" {
		t.Errorf("current_location=%v, want Switzerland", got)
	}
	if got := snap["current_exit_ip"]; got != "45.83.124.18" {
		t.Errorf("current_exit_ip=%v, want 45.83.124.18", got)
	}
	// tunnel_age_seconds is computed from time.Now(); immediately after
	// RecordTunnelUp it rounds to 0 (or close to it). Assert the field
	// exists and is numeric, don't pin to a specific value.
	if _, ok := snap["tunnel_age_seconds"]; !ok {
		t.Error("tunnel_age_seconds missing from snapshot")
	}
}
