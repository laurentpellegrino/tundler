package main

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// vpnProvidersFile mirrors the subset of vpn-providers.yaml that the
// fleet-controller cares about. The full schema (defaults.boot_login_jitter_seconds,
// per-provider excluded_locations, etc.) is for the render script — the
// fleet-controller only needs max_tunnels to seed `configured` (which in
// turn drives both /status totals and the CDS cluster list).
type vpnProvidersFile struct {
	Providers map[string]struct {
		MaxTunnels int `yaml:"max_tunnels"`
	} `yaml:"providers"`
}

// loadConfigured parses vpn-providers.yaml and returns provider->max_tunnels.
// Providers with max_tunnels == 0 are dropped (the design doc treats
// max_tunnels: 0 as "disable this provider" — no StatefulSet, no envoy
// cluster, no /status row).
func loadConfigured(path string) (map[string]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vpn-providers.yaml: %w", err)
	}
	var doc vpnProvidersFile
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse vpn-providers.yaml: %w", err)
	}
	if len(doc.Providers) == 0 {
		return nil, errors.New("vpn-providers.yaml: providers section is empty")
	}
	out := make(map[string]int, len(doc.Providers))
	for name, p := range doc.Providers {
		if p.MaxTunnels < 0 {
			return nil, fmt.Errorf("vpn-providers.yaml: provider %q has negative max_tunnels", name)
		}
		if p.MaxTunnels == 0 {
			continue // disabled
		}
		out[name] = p.MaxTunnels
	}
	if len(out) == 0 {
		return nil, errors.New("vpn-providers.yaml: every provider has max_tunnels: 0 — nothing to serve")
	}
	return out, nil
}
