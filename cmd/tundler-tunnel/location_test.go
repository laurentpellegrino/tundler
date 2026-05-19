package main

import (
	"errors"
	"sort"
	"testing"
)

func TestPickLocation_BasicSelection(t *testing.T) {
	locations := []string{"USA", "UK", "Germany"}
	got, err := pickLocation(locations, nil)
	if err != nil {
		t.Fatalf("pickLocation: %v", err)
	}
	valid := map[string]bool{"USA": true, "UK": true, "Germany": true}
	if !valid[got] {
		t.Errorf("pickLocation returned %q, not in %v", got, locations)
	}
}

func TestPickLocation_ExcludesBlocked(t *testing.T) {
	locations := []string{"USA", "Bahrain", "Yemen", "UK"}
	excluded := []string{"Bahrain", "Yemen"}
	// Run many times to ensure the excluded ones are never picked.
	for i := 0; i < 200; i++ {
		got, err := pickLocation(locations, excluded)
		if err != nil {
			t.Fatalf("iter %d: pickLocation: %v", i, err)
		}
		if got == "Bahrain" || got == "Yemen" {
			t.Fatalf("iter %d: pickLocation returned excluded location %q", i, got)
		}
	}
}

func TestPickLocation_ErrorsWhenAllExcluded(t *testing.T) {
	locations := []string{"Bahrain", "Yemen"}
	excluded := []string{"Bahrain", "Yemen"}
	_, err := pickLocation(locations, excluded)
	if !errors.Is(err, errNoAllowedLocations) {
		t.Errorf("pickLocation got err=%v, want errNoAllowedLocations", err)
	}
}

func TestPickLocation_ErrorsWhenEmptyInput(t *testing.T) {
	_, err := pickLocation(nil, nil)
	if !errors.Is(err, errNoAllowedLocations) {
		t.Errorf("pickLocation(nil, nil) got err=%v, want errNoAllowedLocations", err)
	}
}

func TestPickLocation_RoughlyUniform(t *testing.T) {
	// 4 allowed locations; 4000 picks. Each location should land
	// roughly 1000 ± 200 times. Tolerates random variance but catches
	// gross bugs (e.g., always returning the first element).
	locations := []string{"A", "B", "C", "D"}
	counts := map[string]int{}
	const n = 4000
	for i := 0; i < n; i++ {
		got, err := pickLocation(locations, nil)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		counts[got]++
	}
	expected := n / len(locations)
	for _, loc := range locations {
		c := counts[loc]
		if c < expected-200 || c > expected+200 {
			t.Errorf("%q picked %d times out of %d, want %d ± 200", loc, c, n, expected)
		}
	}
}

func TestParseExcludedLocations(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"Bahrain", []string{"Bahrain"}},
		{"Bahrain,Yemen", []string{"Bahrain", "Yemen"}},
		{" Bahrain , Yemen ", []string{"Bahrain", "Yemen"}},
		{"Bahrain,,Yemen, ", []string{"Bahrain", "Yemen"}},
	}
	for _, c := range cases {
		got := parseExcludedLocations(c.in)
		// sort for stable comparison (parseExcludedLocations preserves order
		// but the test only cares about set semantics)
		sort.Strings(got)
		want := append([]string(nil), c.want...)
		sort.Strings(want)
		if !equalStrings(got, want) {
			t.Errorf("parseExcludedLocations(%q) = %v, want %v", c.in, got, want)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
