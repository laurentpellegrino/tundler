package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRotateHandler_ReadyReturns202(t *testing.T) {
	st := NewStateTracker("fake")
	st.RecordTunnelUp("USA", "1.2.3.4")
	st.Set(StateReady)

	// Channel-based signal: avoids the busy-loop / sleep flakiness of
	// atomic-bool polling. Trigger goroutine sends; test selects with a
	// generous timeout.
	triggered := make(chan struct{}, 1)
	h := rotateHandler(st, func() {
		triggered <- struct{}{}
	})

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/rotate", nil))

	if rr.Code != http.StatusAccepted {
		t.Errorf("got %d, want 202 Accepted", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q, want application/json", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["state"] != string(StateRotating) {
		t.Errorf("state=%q, want Rotating", body["state"])
	}
	if body["previous_exit_ip"] != "1.2.3.4" {
		t.Errorf("previous_exit_ip=%q, want 1.2.3.4", body["previous_exit_ip"])
	}

	select {
	case <-triggered:
		// goroutine fired — expected
	case <-time.After(500 * time.Millisecond):
		t.Error("rotation trigger was not invoked within 500ms")
	}
}

func TestRotateHandler_DrainingReturns200Idempotent(t *testing.T) {
	for _, s := range []State{StateDraining, StateRotating} {
		t.Run(string(s), func(t *testing.T) {
			st := NewStateTracker("fake")
			st.Set(s)

			triggered := false
			h := rotateHandler(st, func() { triggered = true })

			rr := httptest.NewRecorder()
			h(rr, httptest.NewRequest(http.MethodPost, "/rotate", nil))

			if rr.Code != http.StatusOK {
				t.Errorf("state=%s: got %d, want 200 OK (idempotent)", s, rr.Code)
			}
			if triggered {
				t.Errorf("state=%s: trigger should NOT be invoked when already rotating", s)
			}
			var body map[string]string
			if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body["state"] != string(s) {
				t.Errorf("body.state=%q, want %s", body["state"], s)
			}
		})
	}
}

func TestRotateHandler_FailedReturns409Problem(t *testing.T) {
	st := NewStateTracker("fake")
	st.Set(StateFailed)

	triggered := false
	h := rotateHandler(st, func() { triggered = true })

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/rotate", nil))

	if rr.Code != http.StatusConflict {
		t.Errorf("got %d, want 409 Conflict", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type=%q, want application/problem+json", ct)
	}
	var p problemDetails
	if err := json.NewDecoder(rr.Body).Decode(&p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasSuffix(p.Type, "/errors/pod-failed-awaiting-restart") {
		t.Errorf("type=%q, want suffix /errors/pod-failed-awaiting-restart", p.Type)
	}
	if p.Status != http.StatusConflict {
		t.Errorf("status=%d, want 409", p.Status)
	}
	if triggered {
		t.Error("trigger should NOT fire when state is Failed")
	}
}

func TestRotateHandler_NotYetReadyReturns409Problem(t *testing.T) {
	for _, s := range []State{StateBooting, StateLoggingIn, StateConnecting} {
		t.Run(string(s), func(t *testing.T) {
			st := NewStateTracker("fake")
			st.Set(s)

			triggered := false
			h := rotateHandler(st, func() { triggered = true })

			rr := httptest.NewRecorder()
			h(rr, httptest.NewRequest(http.MethodPost, "/rotate", nil))

			if rr.Code != http.StatusConflict {
				t.Errorf("state=%s: got %d, want 409", s, rr.Code)
			}
			if ct := rr.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("state=%s: Content-Type=%q, want application/problem+json", s, ct)
			}
			var p problemDetails
			if err := json.NewDecoder(rr.Body).Decode(&p); err != nil {
				t.Fatalf("state=%s: decode: %v", s, err)
			}
			if !strings.HasSuffix(p.Type, "/errors/not-yet-ready") {
				t.Errorf("state=%s: type=%q, want suffix /errors/not-yet-ready", s, p.Type)
			}
			if !strings.Contains(p.Detail, string(s)) {
				t.Errorf("state=%s: detail=%q should mention the current state", s, p.Detail)
			}
			if triggered {
				t.Errorf("state=%s: trigger should NOT fire", s)
			}
		})
	}
}

func TestRotateHandler_MethodNotAllowed(t *testing.T) {
	st := NewStateTracker("fake")
	st.Set(StateReady)
	h := rotateHandler(st, func() {})

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h(rr, httptest.NewRequest(method, "/rotate", nil))
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("method=%s: got %d, want 405", method, rr.Code)
			}
			if got := rr.Header().Get("Allow"); got != "POST" {
				t.Errorf("Allow header=%q, want POST", got)
			}
		})
	}
}
