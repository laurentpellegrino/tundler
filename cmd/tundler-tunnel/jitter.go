package main

import (
	"math/rand/v2"
	"time"
)

// pickJitter returns a duration uniformly distributed in [0, maxSeconds).
// When maxSeconds <= 0, it returns 0 (jitter disabled).
//
// Extracted as a pure function so the jitter distribution can be unit-tested
// without sleeping: the test calls pickJitter(60) 100× and checks the
// standard deviation is wide enough to spread a fleet of pods boot-logging
// at the same provider auth API.
func pickJitter(maxSeconds int) time.Duration {
	if maxSeconds <= 0 {
		return 0
	}
	return time.Duration(rand.Float64()*float64(maxSeconds)) * time.Second
}
