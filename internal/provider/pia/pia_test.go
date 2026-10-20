package pia

import (
	"reflect"
	"testing"
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
