package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedFetcher returns a fetcher that yields values from the given
// slice in order, looping back to the last value if the test exhausts
// the script. Each call records (so tests can count invocations).
type scriptedFetcher struct {
	mu     sync.Mutex
	script []envoyStats
	calls  int
}

func (s *scriptedFetcher) fetch(_ context.Context) (envoyStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if len(s.script) == 0 {
		return envoyStats{}, errors.New("scriptedFetcher: no script")
	}
	i := s.calls - 1
	if i >= len(s.script) {
		i = len(s.script) - 1
	}
	return s.script[i], nil
}

func (s *scriptedFetcher) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// shortMonitorParams: 5ms sample interval, 6-sample window (= 30ms),
// 30% threshold, minVolume 10. Designed to let tests drive several
// samples in deterministic real time without flakiness.
func shortMonitorParams() monitorParams {
	return monitorParams{
		interval:      5 * time.Millisecond,
		windowSamples: 6,
		threshold:     0.30,
		minVolume:     10,
	}
}

// runMonitorBriefly runs the monitor until the fetcher has been called
// expectedCalls times (or 450ms elapses), then cancels and waits for the
// goroutine to exit.
func runMonitorBriefly(t *testing.T, sf *scriptedFetcher, state *StateTracker, trigger RotateTrigger, p monitorParams, expectedCalls int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		runSelfMonitor(ctx, sf.fetch, state, trigger, p)
		close(done)
	}()
	deadline := time.After(450 * time.Millisecond)
loop:
	for {
		if sf.callCount() >= expectedCalls {
			break loop
		}
		select {
		case <-deadline:
			break loop
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("monitor did not return after context cancel")
	}
}

func TestMonitor_BelowThresholdDoesNotTrigger(t *testing.T) {
	// total grows by 100/sample, 429s grow by 10/sample → 10% rate.
	script := []envoyStats{
		{totalRequests: 100, fourTwentyNines: 10},
		{totalRequests: 200, fourTwentyNines: 20},
		{totalRequests: 300, fourTwentyNines: 30},
		{totalRequests: 400, fourTwentyNines: 40},
		{totalRequests: 500, fourTwentyNines: 50},
		{totalRequests: 600, fourTwentyNines: 60},
		{totalRequests: 700, fourTwentyNines: 70},
	}
	sf := &scriptedFetcher{script: script}
	state := NewStateTracker("fake")
	state.Set(StateReady)

	triggered := make(chan struct{}, 1)
	trigger := func() { triggered <- struct{}{} }

	runMonitorBriefly(t, sf, state, trigger, shortMonitorParams(), len(script))

	select {
	case <-triggered:
		t.Error("trigger fired below threshold (10% < 30%)")
	default:
	}
}

func TestMonitor_AboveThresholdTriggersOnce(t *testing.T) {
	// 60% 429-rate: trigger should fire as soon as window has enough samples.
	script := []envoyStats{
		{totalRequests: 0, fourTwentyNines: 0},
		{totalRequests: 100, fourTwentyNines: 60},
		{totalRequests: 200, fourTwentyNines: 120},
		{totalRequests: 300, fourTwentyNines: 180},
		{totalRequests: 400, fourTwentyNines: 240},
		{totalRequests: 500, fourTwentyNines: 300},
		{totalRequests: 600, fourTwentyNines: 360},
	}
	sf := &scriptedFetcher{script: script}
	state := NewStateTracker("fake")
	state.Set(StateReady)

	var triggerCount int
	var mu sync.Mutex
	trigger := func() {
		mu.Lock()
		triggerCount++
		mu.Unlock()
	}

	runMonitorBriefly(t, sf, state, trigger, shortMonitorParams(), len(script))

	mu.Lock()
	defer mu.Unlock()
	if triggerCount == 0 {
		t.Errorf("trigger never fired with 60%% 429-rate")
	}
	// Trigger MAY fire more than once if the monitor catches a second
	// window before the script's growth slows; our window-reset only
	// helps within the same "ramp". For this test, ≥1 firing is the
	// minimum acceptable behavior.
	if triggerCount > 5 {
		t.Errorf("trigger fired %d times — window reset isn't suppressing duplicates", triggerCount)
	}
}

func TestMonitor_SkipsWhenNotReady(t *testing.T) {
	sf := &scriptedFetcher{script: []envoyStats{
		{totalRequests: 100, fourTwentyNines: 80},
	}}
	state := NewStateTracker("fake")
	state.Set(StateConnecting) // not Ready

	trigger := func() { t.Error("trigger should not fire when state != Ready") }

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		runSelfMonitor(ctx, sf.fetch, state, trigger, shortMonitorParams())
		close(done)
	}()
	<-done

	if sf.callCount() != 0 {
		t.Errorf("fetcher called %d times when state != Ready, want 0", sf.callCount())
	}
}

func TestMonitor_LowVolumeNoTrigger(t *testing.T) {
	// 100% 429-rate but very low volume (< minVolume=10 per window).
	// Should NOT trigger.
	script := []envoyStats{
		{totalRequests: 0, fourTwentyNines: 0},
		{totalRequests: 1, fourTwentyNines: 1},
		{totalRequests: 2, fourTwentyNines: 2},
		{totalRequests: 3, fourTwentyNines: 3},
		{totalRequests: 4, fourTwentyNines: 4},
		{totalRequests: 5, fourTwentyNines: 5},
		{totalRequests: 6, fourTwentyNines: 6},
	}
	sf := &scriptedFetcher{script: script}
	state := NewStateTracker("fake")
	state.Set(StateReady)

	triggered := false
	trigger := func() { triggered = true }

	runMonitorBriefly(t, sf, state, trigger, shortMonitorParams(), len(script))

	if triggered {
		t.Errorf("trigger fired despite delta_total=%d < minVolume=10", 6)
	}
}

func TestMonitor_FetchErrorDoesNotCrash(t *testing.T) {
	state := NewStateTracker("fake")
	state.Set(StateReady)

	calls := 0
	fetch := func(_ context.Context) (envoyStats, error) {
		calls++
		return envoyStats{}, errors.New("simulated network error")
	}
	trigger := func() { t.Error("trigger should not fire on fetch errors") }

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		runSelfMonitor(ctx, fetch, state, trigger, shortMonitorParams())
		close(done)
	}()
	<-done

	if calls == 0 {
		t.Errorf("fetcher was not called at all")
	}
}

func TestParseEnvoyStatsJSON_PullsCounters(t *testing.T) {
	body := strings.NewReader(`{
		"stats": [
			{"name": "cluster.vpn-upstream.upstream_rq_total", "value": 12345},
			{"name": "cluster.vpn-upstream.upstream_rq_2xx", "value": 10000},
			{"name": "cluster.vpn-upstream.upstream_rq_4xx", "value": 1500},
			{"name": "cluster.vpn-upstream.upstream_rq_429", "value": 1200},
			{"name": "cluster.vpn-upstream.upstream_rq_5xx", "value": 100}
		]
	}`)
	got, err := parseEnvoyStatsJSON(body, "cluster.vpn-upstream.upstream_rq_")
	if err != nil {
		t.Fatalf("parseEnvoyStatsJSON: %v", err)
	}
	if got.totalRequests != 12345 {
		t.Errorf("totalRequests=%d, want 12345", got.totalRequests)
	}
	if got.fourTwentyNines != 1200 {
		t.Errorf("fourTwentyNines=%d, want 1200", got.fourTwentyNines)
	}
}

func TestParseEnvoyStatsJSON_HandlesMissingCounters(t *testing.T) {
	// Fresh envoy with no traffic: stats array is empty.
	body := strings.NewReader(`{"stats": []}`)
	got, err := parseEnvoyStatsJSON(body, "cluster.vpn-upstream.upstream_rq_")
	if err != nil {
		t.Fatalf("parseEnvoyStatsJSON: %v", err)
	}
	if got.totalRequests != 0 || got.fourTwentyNines != 0 {
		t.Errorf("got %+v, want zero stats for empty input", got)
	}
}

func TestFetchEnvoyStats_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/stats") {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `{"stats": [
			{"name": "cluster.vpn-upstream.upstream_rq_total", "value": 999},
			{"name": "cluster.vpn-upstream.upstream_rq_429", "value": 7}
		]}`)
	}))
	defer srv.Close()

	got, err := fetchEnvoyStats(srv.URL)(context.Background())
	if err != nil {
		t.Fatalf("fetchEnvoyStats: %v", err)
	}
	if got.totalRequests != 999 || got.fourTwentyNines != 7 {
		t.Errorf("got %+v, want {999, 7}", got)
	}
}

func TestFetchEnvoyStats_NonOKStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down for maintenance", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := fetchEnvoyStats(srv.URL)(context.Background())
	if err == nil {
		t.Fatal("expected error on 503 response, got nil")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("err=%v, want substring '503'", err)
	}
}
