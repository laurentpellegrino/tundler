package surfshark

import (
	"context"
	"testing"
)

func resetActiveState(t *testing.T) {
	t.Helper()
	activeServer = nil
	activeProtocol = ""
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
}

// TestActiveLocationRoundTrip pins the contract that ActiveLocation
// returns the verbatim string passed to Connect, so a value pulled
// from Locations() (the candidate pool the manager picks from) and
// stamped onto Status.Location can be matched byte-for-byte against a
// config block/allow entry.
func TestActiveLocationRoundTrip(t *testing.T) {
	resetActiveState(t)
	t.Cleanup(func() { resetActiveState(t) })

	activeServer = &Server{Country: "United States", Location: "New York"}
	activeMu.Lock()
	activeLocation = "United States"
	activeMu.Unlock()

	if got := (Surfshark{}).ActiveLocation(context.Background()); got != "United States" {
		t.Fatalf("ActiveLocation = %q, want %q", got, "United States")
	}
}

// Without an active server the provider is not connected, so a stale
// activeLocation must not leak out.
func TestActiveLocationEmptyWhenDisconnected(t *testing.T) {
	resetActiveState(t)
	t.Cleanup(func() { resetActiveState(t) })

	activeMu.Lock()
	activeLocation = "United States"
	activeMu.Unlock()

	if got := (Surfshark{}).ActiveLocation(context.Background()); got != "" {
		t.Fatalf("ActiveLocation while disconnected = %q, want empty", got)
	}
}

func TestDisconnectClearsActiveLocation(t *testing.T) {
	resetActiveState(t)
	t.Cleanup(func() { resetActiveState(t) })

	activeServer = &Server{Country: "United States"}
	activeProtocol = "openvpn"
	activeMu.Lock()
	activeLocation = "United States"
	activeMu.Unlock()

	// Disconnect calls `pkill openvpn`, which is fine even when openvpn
	// isn't running (RunCmd swallows the non-zero exit). The state we
	// care about is cleared on the way out.
	if err := (Surfshark{}).Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect error: %v", err)
	}
	if activeServer != nil {
		t.Fatalf("activeServer not cleared after Disconnect")
	}
	if activeProtocol != "" {
		t.Fatalf("activeProtocol not cleared after Disconnect: %q", activeProtocol)
	}
	activeMu.RLock()
	got := activeLocation
	activeMu.RUnlock()
	if got != "" {
		t.Fatalf("activeLocation after Disconnect = %q, want empty", got)
	}
}
