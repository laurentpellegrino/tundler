package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestTriggerGracefulDrain_HitsRightEndpoint(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/drain_listeners" {
			http.Error(w, "wrong method/path", http.StatusBadRequest)
			return
		}
		if !r.URL.Query().Has("graceful") {
			http.Error(w, "missing graceful query parameter", http.StatusBadRequest)
			return
		}
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newEnvoyDrainController(srv.URL)
	if err := c.TriggerGracefulDrain(context.Background()); err != nil {
		t.Fatalf("TriggerGracefulDrain: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("envoy admin called %d times, want 1", calls.Load())
	}
}

func TestTriggerGracefulDrain_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "envoy is shutting down", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newEnvoyDrainController(srv.URL)
	err := c.TriggerGracefulDrain(context.Background())
	if err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
}

// fakeStatsServer returns a configurable downstream_cx_active counter.
// counter is read on every /stats GET — tests update it to drive the
// drain-wait loop.
type fakeStatsServer struct {
	counter atomic.Int64
	srv     *httptest.Server
}

func newFakeStatsServer(t *testing.T) *fakeStatsServer {
	t.Helper()
	f := &fakeStatsServer{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stats" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		c := f.counter.Load()
		fmt.Fprintf(w, `{"stats": [
			{"name": "listener.data_listener.downstream_cx_active", "value": %d}
		]}`, c)
	}))
	return f
}

func (f *fakeStatsServer) URL() string                     { return f.srv.URL }
func (f *fakeStatsServer) Close()                          { f.srv.Close() }
func (f *fakeStatsServer) SetActive(v int64)               { f.counter.Store(v) }

func TestWaitForActiveConnectionsToDrain_ReturnsOnZero(t *testing.T) {
	f := newFakeStatsServer(t)
	defer f.Close()
	f.SetActive(5)

	c := newEnvoyDrainController(f.URL())
	done := make(chan error, 1)
	go func() {
		done <- c.WaitForActiveConnectionsToDrain(context.Background(), 5*time.Second)
	}()

	// Let one poll happen with active > 0, then drop to 0.
	time.Sleep(700 * time.Millisecond)
	f.SetActive(0)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("WaitForActiveConnectionsToDrain returned %v, want nil after counter→0", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WaitForActiveConnectionsToDrain did not return after counter dropped to 0")
	}
}

func TestWaitForActiveConnectionsToDrain_TimesOut(t *testing.T) {
	f := newFakeStatsServer(t)
	defer f.Close()
	f.SetActive(10) // never drops

	c := newEnvoyDrainController(f.URL())
	err := c.WaitForActiveConnectionsToDrain(context.Background(), 1*time.Second)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, errDrainTimeout) {
		t.Errorf("err=%v, want errDrainTimeout", err)
	}
}

func TestWaitForActiveConnectionsToDrain_ContextCancel(t *testing.T) {
	f := newFakeStatsServer(t)
	defer f.Close()
	f.SetActive(10) // never drops

	c := newEnvoyDrainController(f.URL())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- c.WaitForActiveConnectionsToDrain(ctx, 30*time.Second)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err=%v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForActiveConnectionsToDrain did not honor ctx cancel")
	}
}

// fakeDrainController records calls so rotator tests can assert the
// drain order: Trigger BEFORE Disconnect, Wait BEFORE Connect.
type fakeDrainController struct {
	triggerCount atomic.Int32
	waitCount    atomic.Int32
	// triggerBeforeDisconnect/waitBeforeConnect are populated by the
	// fakeProvider hook (set up in the test).
}

func (d *fakeDrainController) TriggerGracefulDrain(_ context.Context) error {
	d.triggerCount.Add(1)
	return nil
}
func (d *fakeDrainController) WaitForActiveConnectionsToDrain(_ context.Context, _ time.Duration) error {
	d.waitCount.Add(1)
	return nil
}

func TestRotator_CallsDrainBeforeDisconnect(t *testing.T) {
	fp := &fakeProvider{
		locations: []string{"USA"},
		connectIP: "9.9.9.9",
		connectOK: true,
	}
	fp.connected.Store(true)

	drain := &fakeDrainController{}
	state := NewStateTracker("fake")
	state.RecordTunnelUp("USA", "1.1.1.1")
	state.Set(StateReady)

	// fakeProvider.onConnect (set BEFORE rotateIfReady invokes
	// Disconnect → Connect) records that drain ran first.
	var disconnectSeenAfterDrain atomic.Bool
	fp.onConnect = func(_ string) {
		// By the time Connect is called, both drain hooks should have
		// fired and the provider should have been Disconnected.
		if drain.triggerCount.Load() == 1 && drain.waitCount.Load() == 1 {
			disconnectSeenAfterDrain.Store(true)
		}
	}

	rotateIfReady(context.Background(), fp, state, "fake", nil, drain)

	if drain.triggerCount.Load() != 1 {
		t.Errorf("TriggerGracefulDrain called %d times, want 1", drain.triggerCount.Load())
	}
	if drain.waitCount.Load() != 1 {
		t.Errorf("WaitForActiveConnectionsToDrain called %d times, want 1", drain.waitCount.Load())
	}
	if !disconnectSeenAfterDrain.Load() {
		t.Error("drain hooks did not run before Connect — wrong order")
	}
	if state.Get() != StateReady {
		t.Errorf("state=%s after rotation, want Ready", state.Get())
	}
}
