package main

import (
	"sort"
	"testing"
)

func TestStatusSnapshot_IncludesEveryConfiguredProvider(t *testing.T) {
	fc := newFleetController(map[string]int{
		"expressvpn": 7,
		"nordvpn":    9,
		"protonvpn":  8,
	})
	// Only one provider has any healthy pods — the others should still
	// appear in the response with healthy=0.
	fc.healthy["expressvpn"] = 6
	fc.podAddrs["expressvpn"] = []string{"10.0.0.1", "10.0.0.2"}

	snap := fc.statusSnapshot()
	if got, want := len(snap.Providers), 3; got != want {
		t.Errorf("len(providers)=%d, want %d", got, want)
	}
	if snap.Providers["protonvpn"].Configured != 8 || snap.Providers["protonvpn"].Healthy != 0 {
		t.Errorf("protonvpn=%v, want configured=8 healthy=0", snap.Providers["protonvpn"])
	}
	if snap.Providers["expressvpn"].Healthy != 6 {
		t.Errorf("expressvpn.healthy=%d, want 6", snap.Providers["expressvpn"].Healthy)
	}
	if snap.TotalConfigured != 24 {
		t.Errorf("total_configured=%d, want 24", snap.TotalConfigured)
	}
	if snap.TotalHealthy != 6 {
		t.Errorf("total_healthy=%d, want 6", snap.TotalHealthy)
	}
}

func TestServiceForTunnelID(t *testing.T) {
	fc := newFleetController(map[string]int{"expressvpn": 7})
	fc.podToService["tundler-tunnel-expressvpn-0"] = "tundler-tunnel-expressvpn"
	fc.podToService["tundler-tunnel-expressvpn-3"] = "tundler-tunnel-expressvpn"

	if got, ok := fc.serviceForTunnelID("tundler-tunnel-expressvpn-3"); !ok || got != "tundler-tunnel-expressvpn" {
		t.Errorf("serviceForTunnelID(known)=(%q,%v), want (tundler-tunnel-expressvpn,true)", got, ok)
	}
	if _, ok := fc.serviceForTunnelID("tundler-tunnel-foo-99"); ok {
		t.Error("serviceForTunnelID(unknown) returned ok=true, want false")
	}
}

func TestStatusSnapshot_OrderingStableForGivenInput(t *testing.T) {
	fc := newFleetController(map[string]int{
		"a": 1, "b": 2, "c": 3, "d": 4,
	})
	snap := fc.statusSnapshot()
	keys := make([]string, 0, len(snap.Providers))
	for k := range snap.Providers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if got, want := keys, []string{"a", "b", "c", "d"}; !equalSlices(got, want) {
		t.Errorf("providers=%v, want %v", got, want)
	}
}

func equalSlices(a, b []string) bool {
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
