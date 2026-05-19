package main

import (
	"math"
	"testing"
)

// TestPickJitter_Disabled asserts that BOOT_LOGIN_JITTER_SECONDS=0 (or
// negative) returns a zero duration. Matches the design-doc edge case:
// "BOOT_LOGIN_JITTER_SECONDS=0; assert all 100 instances sleep 0 s."
func TestPickJitter_Disabled(t *testing.T) {
	for _, max := range []int{0, -1, -100} {
		got := pickJitter(max)
		if got != 0 {
			t.Errorf("pickJitter(%d) = %v, want 0", max, got)
		}
	}
}

// TestPickJitter_WideDistribution asserts that with BOOT_LOGIN_JITTER_SECONDS=60,
// 100 invocations produce sleep durations whose standard deviation exceeds
// 12 s (about 70% of the theoretical stddev of a uniform [0, 60s] = 60/√12 ≈
// 17.3 s, leaving margin against random variance). This is the design-doc
// "Boot-login jitter (distinct from rotation-timer jitter)" test: proves the
// fleet of pods doesn't synchronously hammer the provider auth API.
func TestPickJitter_WideDistribution(t *testing.T) {
	const (
		maxSec    = 60
		n         = 100
		minStdDev = 12.0 // seconds
	)

	samples := make([]float64, n)
	var sum float64
	for i := range samples {
		samples[i] = pickJitter(maxSec).Seconds()
		sum += samples[i]
	}
	mean := sum / float64(n)

	var sumSq float64
	for _, s := range samples {
		sumSq += (s - mean) * (s - mean)
	}
	stdDev := math.Sqrt(sumSq / float64(n))

	if stdDev < minStdDev {
		t.Errorf("pickJitter(%d) stddev = %.2fs over %d samples, want > %.1fs (jitter too narrow)",
			maxSec, stdDev, n, minStdDev)
	}

	for _, s := range samples {
		if s < 0 || s >= float64(maxSec) {
			t.Errorf("pickJitter(%d) returned %.2fs, want in [0, %d)", maxSec, s, maxSec)
		}
	}
}

// TestPickJitter_PIAWideDistribution does the same check for the PIA-specific
// jitter window (180 s). The design doc calls out PIA's larger window
// explicitly because its auth API is the most sensitive — the wider spread
// is what keeps fleet-wide login storms below the rate limit.
func TestPickJitter_PIAWideDistribution(t *testing.T) {
	const (
		maxSec    = 180
		n         = 100
		minStdDev = 38.0 // ≈ 70% of 180/√12 ≈ 52
	)

	samples := make([]float64, n)
	var sum float64
	for i := range samples {
		samples[i] = pickJitter(maxSec).Seconds()
		sum += samples[i]
	}
	mean := sum / float64(n)

	var sumSq float64
	for _, s := range samples {
		sumSq += (s - mean) * (s - mean)
	}
	stdDev := math.Sqrt(sumSq / float64(n))

	if stdDev < minStdDev {
		t.Errorf("pickJitter(%d) stddev = %.2fs over %d samples, want > %.1fs",
			maxSec, stdDev, n, minStdDev)
	}
}
