package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "vpn-providers.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write tempfile: %v", err)
	}
	return p
}

func TestLoadConfigured_HappyPath(t *testing.T) {
	p := writeTempYAML(t, `
defaults:
  min_rotation_seconds: 3600
providers:
  expressvpn:
    max_tunnels: 7
  nordvpn:
    max_tunnels: 9
    excluded_locations: [Bahrain]
`)
	got, err := loadConfigured(p)
	if err != nil {
		t.Fatalf("loadConfigured: %v", err)
	}
	want := map[string]int{"expressvpn": 7, "nordvpn": 9}
	if len(got) != len(want) {
		t.Fatalf("got=%v, want=%v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("got[%q]=%d, want %d", k, got[k], v)
		}
	}
}

func TestLoadConfigured_ZeroMaxTunnelsIsDisabled(t *testing.T) {
	p := writeTempYAML(t, `
providers:
  expressvpn:
    max_tunnels: 7
  legacy:
    max_tunnels: 0
`)
	got, err := loadConfigured(p)
	if err != nil {
		t.Fatalf("loadConfigured: %v", err)
	}
	if _, present := got["legacy"]; present {
		t.Errorf("legacy provider with max_tunnels=0 should have been dropped, got %v", got)
	}
	if got["expressvpn"] != 7 {
		t.Errorf("expressvpn=%d, want 7", got["expressvpn"])
	}
}

func TestLoadConfigured_NegativeMaxTunnelsErrors(t *testing.T) {
	p := writeTempYAML(t, `
providers:
  expressvpn:
    max_tunnels: -1
`)
	_, err := loadConfigured(p)
	if err == nil {
		t.Fatal("expected error for negative max_tunnels, got nil")
	}
	if !strings.Contains(err.Error(), "negative") {
		t.Errorf("err=%v, want it to mention 'negative'", err)
	}
}

func TestLoadConfigured_EmptyProvidersErrors(t *testing.T) {
	p := writeTempYAML(t, `defaults:
  min_rotation_seconds: 3600
`)
	_, err := loadConfigured(p)
	if err == nil {
		t.Fatal("expected error for missing providers section, got nil")
	}
}

func TestLoadConfigured_AllZeroErrors(t *testing.T) {
	p := writeTempYAML(t, `
providers:
  a:
    max_tunnels: 0
  b:
    max_tunnels: 0
`)
	_, err := loadConfigured(p)
	if err == nil {
		t.Fatal("expected error when every provider is disabled, got nil")
	}
}

func TestLoadConfigured_MissingFileErrors(t *testing.T) {
	_, err := loadConfigured("/nonexistent/path/to/vpn-providers.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadConfigured_BadYAMLErrors(t *testing.T) {
	p := writeTempYAML(t, "this: is: not: valid: yaml")
	_, err := loadConfigured(p)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}
