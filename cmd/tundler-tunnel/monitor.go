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

// envoyStats is a snapshot of the cumulative upstream-request counters
// the self-monitor cares about. Both fields are monotonically increasing
// counters reported by envoy's admin /stats endpoint.
type envoyStats struct {
	totalRequests   int64
	fourTwentyNines int64
}

// statsFetcher abstracts the GET to envoy admin so tests can drive the
// monitor without an actual envoy. Production wires fetchEnvoyStats(url);
// tests pass a stub that returns canned values.
type statsFetcher func(ctx context.Context) (envoyStats, error)

// monitorParams are the tunable knobs for the self-monitor. Defaults
// align with the design-doc Trigger C: "if its tunnel's 429-rate > 30%
// over 60 s, calls SwitchLocation".
type monitorParams struct {
	interval      time.Duration // how often to sample envoy admin
	windowSamples int           // sliding window size; window seconds = interval × windowSamples
	threshold     float64       // 0.30 = 30% 429-rate triggers rotation
	minVolume     int64         // ignore windows with fewer than this many total requests
}

// defaultMonitorParams returns the production defaults. Sample every 10s,
// window over the last 6 samples (= 60s), threshold 30%, ignore windows
// with fewer than 10 requests (not enough signal to act on).
func defaultMonitorParams() monitorParams {
	return monitorParams{
		interval:      10 * time.Second,
		windowSamples: 6,
		threshold:     0.30,
		minVolume:     10,
	}
}

// runSelfMonitor implements Trigger C from the design doc: tundler-tunnel
// watches its own envoy's upstream 4xx counters and proactively rotates
// when its exit IP starts getting hammered with 429s. Stays out when
// state != Ready (other code paths own the connection lifecycle then).
//
// On a triggered rotation, the window is reset so we don't immediately
// fire again on the next sample if the rotation is still draining.
func runSelfMonitor(ctx context.Context, fetch statsFetcher, state *StateTracker, trigger RotateTrigger, params monitorParams) {
	samples := make([]envoyStats, 0, params.windowSamples+1)
	ticker := time.NewTicker(params.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if state.Get() != StateReady {
				// Don't sample during transitions — counters reset on
				// envoy config reload anyway, and a paused window
				// keeps the rate calc honest.
				continue
			}
			stats, err := fetch(ctx)
			if err != nil {
				log.Printf("self-monitor: stats fetch failed: %v", err)
				continue
			}
			samples = append(samples, stats)
			if len(samples) > params.windowSamples {
				samples = samples[1:]
			}
			if len(samples) < 2 {
				continue // need at least 2 samples to compute a delta
			}
			oldest := samples[0]
			newest := samples[len(samples)-1]
			deltaTotal := newest.totalRequests - oldest.totalRequests
			deltaFTN := newest.fourTwentyNines - oldest.fourTwentyNines
			if deltaTotal < params.minVolume {
				continue
			}
			rate := float64(deltaFTN) / float64(deltaTotal)
			if rate > params.threshold {
				log.Printf("self-monitor: 429-rate %.1f%% > threshold %.1f%% over %s window (delta_total=%d, delta_429=%d) — triggering rotation",
					rate*100, params.threshold*100,
					time.Duration(len(samples))*params.interval,
					deltaTotal, deltaFTN)
				go trigger()
				// Reset window: post-rotation, envoy is fresh and the
				// previous counters aren't meaningful anymore. Without
				// this we'd fire repeatedly on each sample until the
				// window naturally rolled past the high-rate period.
				samples = samples[:0]
			}
		}
	}
}

// fetchEnvoyStats builds a statsFetcher that GETs envoy admin /stats
// (JSON format) and pulls out the cluster.<ClusterName>.upstream_rq_*
// counters. Production passes "http://127.0.0.1:9901" — envoy admin is
// loopback-only per the design's bind-address decision.
func fetchEnvoyStats(adminURL string) statsFetcher {
	clusterPrefix := "cluster.vpn-upstream.upstream_rq_"
	return func(ctx context.Context) (envoyStats, error) {
		url := adminURL + "/stats?format=json&filter=" + clusterPrefix
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return envoyStats{}, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return envoyStats{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return envoyStats{}, fmt.Errorf("envoy admin status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return parseEnvoyStatsJSON(resp.Body, clusterPrefix)
	}
}

// envoyStatsResp matches the subset of envoy's /stats?format=json output
// we care about. `value` is uint64 in envoy but JSON encodes large
// numbers as float64 in encoding/json by default; we use json.Number
// to keep the int precision.
type envoyStatsResp struct {
	Stats []struct {
		Name  string      `json:"name"`
		Value json.Number `json:"value"`
	} `json:"stats"`
}

// parseEnvoyStatsJSON extracts the request counters from envoy's stats
// response. Looks for two specific suffixes:
//   - "<prefix>total" → totalRequests (running sum of completed upstream requests)
//   - "<prefix>429"   → fourTwentyNines (count of 429 responses observed)
//
// Returns envoyStats with whatever was found; missing names default to 0
// (which is correct on a fresh envoy with no traffic yet).
func parseEnvoyStatsJSON(r io.Reader, prefix string) (envoyStats, error) {
	var resp envoyStatsResp
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return envoyStats{}, fmt.Errorf("decode envoy stats: %w", err)
	}
	out := envoyStats{}
	for _, s := range resp.Stats {
		switch s.Name {
		case prefix + "total":
			v, err := s.Value.Int64()
			if err != nil {
				return envoyStats{}, fmt.Errorf("parse %s value %q: %w", s.Name, s.Value, err)
			}
			out.totalRequests = v
		case prefix + "429":
			v, err := s.Value.Int64()
			if err != nil {
				return envoyStats{}, fmt.Errorf("parse %s value %q: %w", s.Name, s.Value, err)
			}
			out.fourTwentyNines = v
		}
	}
	return out, nil
}

