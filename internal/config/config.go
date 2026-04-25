package config

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
)

type LocationFilter struct {
	Allow []string
	Block []string
}

type Provider struct {
	Locations LocationFilter
}

type Config struct {
	Debug     bool
	Telemetry bool
	Providers map[string]Provider
	Plugins   []string
}

// Load reads a very small subset of YAML from path. Missing file yields an empty configuration.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{Providers: map[string]Provider{}}, nil
		}
		return nil, err
	}

	cfg := &Config{Providers: map[string]Provider{}}
	var current string
	var inPlugins bool
	var inLocations, inAllow, inBlock bool

	resetSections := func() {
		inPlugins = false
		inLocations = false
		inAllow = false
		inBlock = false
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "debug:"):
			val := strings.TrimSpace(strings.TrimPrefix(line, "debug:"))
			cfg.Debug = val == "true"
			resetSections()
		case strings.HasPrefix(line, "telemetry:"):
			val := strings.TrimSpace(strings.TrimPrefix(line, "telemetry:"))
			cfg.Telemetry = val == "true"
			resetSections()
		case strings.HasPrefix(line, "providers:"):
			resetSections()
		case strings.HasPrefix(line, "plugins:"):
			resetSections()
			inPlugins = true
		case strings.HasPrefix(line, "- ") && strings.HasSuffix(line, ":"):
			current = strings.TrimSuffix(strings.TrimPrefix(line, "- "), ":")
			cfg.Providers[current] = Provider{}
			resetSections()
		case inPlugins && strings.HasPrefix(line, "- "):
			cfg.Plugins = append(cfg.Plugins, strings.TrimSpace(strings.TrimPrefix(line, "- ")))
		case strings.HasPrefix(line, "locations:"):
			inLocations = true
			inAllow = false
			inBlock = false
		case inLocations && strings.HasPrefix(line, "allow:"):
			inAllow = true
			inBlock = false
		case inLocations && strings.HasPrefix(line, "block:"):
			inBlock = true
			inAllow = false
		case inAllow && strings.HasPrefix(line, "- "):
			loc := strings.TrimSpace(strings.TrimPrefix(line, "- "))
			p := cfg.Providers[current]
			p.Locations.Allow = append(p.Locations.Allow, loc)
			cfg.Providers[current] = p
		case inBlock && strings.HasPrefix(line, "- "):
			loc := strings.TrimSpace(strings.TrimPrefix(line, "- "))
			p := cfg.Providers[current]
			p.Locations.Block = append(p.Locations.Block, loc)
			cfg.Providers[current] = p
		case inLocations && strings.HasPrefix(line, "- "):
			log.Printf("[config] provider %s: legacy flat 'locations:' list is no longer supported; "+
				"use 'locations: { allow: [...], block: [...] }' instead (entry %q ignored)",
				current, strings.TrimSpace(strings.TrimPrefix(line, "- ")))
		}
	}
	return cfg, sc.Err()
}
