package config

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"strings"
)

type Provider struct {
	Locations []string
}

type Config struct {
	Debug     bool
	Telemetry bool
	Providers map[string]Provider
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
	var inLocations bool
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
		case strings.HasPrefix(line, "telemetry:"):
			val := strings.TrimSpace(strings.TrimPrefix(line, "telemetry:"))
			cfg.Telemetry = val == "true"
		case strings.HasPrefix(line, "providers:"):
			// no-op
		case strings.HasPrefix(line, "- ") && strings.HasSuffix(line, ":"):
			current = strings.TrimSuffix(strings.TrimPrefix(line, "- "), ":")
			cfg.Providers[current] = Provider{}
			inLocations = false
		case strings.HasPrefix(line, "locations:"):
			inLocations = true
		case inLocations && strings.HasPrefix(line, "- "):
			loc := strings.TrimSpace(strings.TrimPrefix(line, "- "))
			p := cfg.Providers[current]
			p.Locations = append(p.Locations, loc)
			cfg.Providers[current] = p
		}
	}
	return cfg, sc.Err()
}
