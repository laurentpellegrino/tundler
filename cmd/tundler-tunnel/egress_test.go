package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func noBaselineWait(context.Context, time.Duration) bool { return true }

func TestProbeBaselineEgressIPRetriesAfterAFailure(t *testing.T) {
	calls := 0
	probe := func(context.Context) (string, error) {
		calls++
		if calls == 1 {
			return "", context.DeadlineExceeded
		}
		return "203.0.113.7", nil
	}
	ip, err := probeBaselineEgressIP(context.Background(), probe, 3, noBaselineWait)
	if err != nil || ip != "203.0.113.7" {
		t.Fatalf("got %q, %v; want the second answer", ip, err)
	}
	if calls != 2 {
		t.Fatalf("probe called %d times, want 2", calls)
	}
}

func TestProbeBaselineEgressIPGivesUpAfterTheLastAttempt(t *testing.T) {
	calls, waits := 0, 0
	probe := func(context.Context) (string, error) {
		calls++
		return "", errors.New("unreachable")
	}
	wait := func(context.Context, time.Duration) bool { waits++; return true }
	ip, err := probeBaselineEgressIP(context.Background(), probe, 3, wait)
	if err == nil || ip != "" {
		t.Fatalf("got %q, %v; want an error", ip, err)
	}
	if calls != 3 || waits != 2 {
		t.Fatalf("calls %d waits %d, want 3 and 2", calls, waits)
	}
}

func TestProbeBaselineEgressIPTreatsAnEmptyAnswerAsAFailure(t *testing.T) {
	answers := []string{"", "198.51.100.2"}
	probe := func(context.Context) (string, error) {
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
	ip, err := probeBaselineEgressIP(context.Background(), probe, 3, noBaselineWait)
	if err != nil || ip != "198.51.100.2" {
		t.Fatalf("got %q, %v", ip, err)
	}
}

func TestProbeBaselineEgressIPStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	probe := func(context.Context) (string, error) {
		calls++
		cancel()
		return "", errors.New("timeout")
	}
	_, err := probeBaselineEgressIP(ctx, probe, 3, sleepCtx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Fatalf("probe called %d times, want 1", calls)
	}
}
