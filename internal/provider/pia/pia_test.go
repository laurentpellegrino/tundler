package pia

import (
	"reflect"
	"testing"

	"github.com/laurentpellegrino/tundler/internal/provider"
)

func TestParseRegionsSkipsTimeoutLine(t *testing.T) {
	got := parseRegions("auto\n# comment\nTimed out after 5.001 sec\n\nbelgium\n")
	if want := []string{"auto", "belgium"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("parseRegions = %v, want %v", got, want)
	}
}

func TestDaemonInactive(t *testing.T) {
	if !daemonInactive("Cannot connect - start the PIA client to activate the daemon, or use `piactl background enable` to enable background mode.") {
		t.Fatal("inactive-daemon message not recognised")
	}
	if daemonInactive("") || daemonInactive("Connected") {
		t.Fatal("false positive")
	}
}

func TestConnectedWithoutVPNIPCountsAsFailed(t *testing.T) {
	got, failed := withoutVPNIPFailed(provider.Status{Connected: true, Provider: name, Location: "netherlands"})
	if !failed || got.Connected {
		t.Fatalf("connected with no IP: got %+v failed=%v, want a failed status", got, failed)
	}
	if got.Location != "netherlands" || got.AuthFailed || got.Throttled {
		t.Fatalf("other fields changed: %+v", got)
	}
	up := provider.Status{Connected: true, IP: "158.173.21.129", Provider: name}
	if got, failed := withoutVPNIPFailed(up); failed || got != up {
		t.Fatalf("connected with an IP: got %+v failed=%v, want it unchanged", got, failed)
	}
	down := provider.Status{Provider: name}
	if got, failed := withoutVPNIPFailed(down); failed || got != down {
		t.Fatalf("not connected: got %+v failed=%v, want it unchanged", got, failed)
	}
}
