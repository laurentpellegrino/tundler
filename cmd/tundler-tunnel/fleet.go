package main

// Fleet layout from the topology file.
//
// The region-spread preference (preference.go) needs every pod to agree
// on where each provider's block starts on the shared country ring.
// Historically the deployment renderer baked that agreement into three
// static env vars per StatefulSet, which made every topology edit
// (enabling a provider, resizing one) a fleet-wide pod roll because the
// base of each later provider and the fleet total moved.
//
// Instead the pod can read the fleet topology itself: the renderer
// already publishes vpn-providers.yaml as a ConfigMap, mounted into the
// pod as a plain file. Every pod derives the SAME layout from the same
// document with the same rule the renderer used — providers in sorted
// order, each holding a contiguous block of max_tunnels slots — and
// re-reads the file at every pick, so a topology change lands at the
// next rotation of each pod with no restart. The env vars remain the
// fallback for deployments that do not mount the file.

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

const (
	// envFleetLayout overrides the path of the mounted topology file.
	envFleetLayout     = "TUNDLER_FLEET_LAYOUT"
	defaultFleetLayout = "/etc/tundler/fleet/vpn-providers.yaml"
)

// fleetLayout is one provider's block in the fleet-global slot space.
type fleetLayout struct {
	base     int // first fleet-global slot of the provider's block
	slots    int // fleet-wide pod total
	replicas int // the provider's own pod count (block width)
}

// fleetLayoutPath is the topology file to read: the env override or the
// default mount path.
func fleetLayoutPath() string {
	if p := os.Getenv(envFleetLayout); p != "" {
		return p
	}
	return defaultFleetLayout
}

// parseFleetLayout derives provider's block from a vpn-providers.yaml
// document: providers sorted by name each take a contiguous block of
// max_tunnels slots (the renderer's rule, kept verbatim so a fleet that
// mixes file-driven and env-driven pods agrees on the layout).
func parseFleetLayout(doc []byte, provider string) (fleetLayout, error) {
	var topo struct {
		Providers map[string]struct {
			MaxTunnels int `yaml:"max_tunnels"`
		} `yaml:"providers"`
	}
	if err := yaml.Unmarshal(doc, &topo); err != nil {
		return fleetLayout{}, fmt.Errorf("parse topology: %w", err)
	}
	own, ok := topo.Providers[provider]
	if !ok {
		return fleetLayout{}, fmt.Errorf("provider %q not in topology", provider)
	}
	names := make([]string, 0, len(topo.Providers))
	for name := range topo.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	var l fleetLayout
	for _, name := range names {
		n := topo.Providers[name].MaxTunnels
		if n < 0 {
			return fleetLayout{}, fmt.Errorf("provider %q: negative max_tunnels %d", name, n)
		}
		if name == provider {
			l.base = l.slots
		}
		l.slots += n
	}
	l.replicas = own.MaxTunnels
	if l.slots <= 0 {
		return fleetLayout{}, fmt.Errorf("topology has no tunnels")
	}
	return l, nil
}

// readFleetLayout loads provider's block from the topology file at path.
func readFleetLayout(path, provider string) (fleetLayout, error) {
	doc, err := os.ReadFile(path)
	if err != nil {
		return fleetLayout{}, err
	}
	return parseFleetLayout(doc, provider)
}
