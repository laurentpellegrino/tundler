package hideme

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// catalogFile is hide.me's public server list, baked into the image by
// docker/providers/hideme/install.sh (the daily image rebuild refreshes
// it). It is the same list the official client prints with `list`.
const catalogFile = "/etc/hideme/servers.json"

// server is one connectable hide.me server: the REST hostname the
// client connects to, and where it is.
type server struct {
	Name     string // tundler location name, e.g. "nl", "de-frankfurt-1", "gb-free"
	Hostname string // e.g. "frankfurt1-v4.hideservers.net"
	Country  string // ISO alpha-2, upper case
	City     string
}

// catalogEntry is the subset of a server-list entry this package reads.
// Entries nest: a country with several servers lists them as children,
// and the parent's hostname picks one of them.
type catalogEntry struct {
	Hostname    string         `json:"hostname"`
	DisplayName string         `json:"displayName"`
	Tags        []string       `json:"tags"`
	Geo         catalogGeo     `json:"geo"`
	Children    []catalogEntry `json:"children"`
}

type catalogGeo struct {
	CityName    string `json:"cityName"`
	CountryCode string `json:"countryCode"`
}

var (
	catalogMu    sync.Mutex
	catalogCache []server
)

// loadCatalog reads and parses catalogFile once per process.
func loadCatalog() ([]server, error) {
	catalogMu.Lock()
	defer catalogMu.Unlock()
	if len(catalogCache) > 0 {
		return catalogCache, nil
	}
	data, err := os.ReadFile(catalogFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", catalogFile, err)
	}
	servers, err := parseCatalog(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", catalogFile, err)
	}
	catalogCache = servers
	return servers, nil
}

// parseCatalog turns the server list into one location per leaf server.
// A country with children contributes its children only: the parent's
// hostname is a group that lands on one of them, so listing it too would
// only duplicate exits under a second name. Names start with the lower
// case country code so the region walk maps them to a country:
// "nl" for a country with a single server, "<cc>-<city slug>" for a
// child ("us-texas-dallas", "fi-helsinki-1"), "<cc>-free" for the free
// servers.
func parseCatalog(data []byte) ([]server, error) {
	var entries []catalogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	var servers []server
	seenHost := map[string]bool{}
	seenName := map[string]int{}
	add := func(e catalogEntry, name string) {
		host := strings.ToLower(strings.TrimSpace(e.Hostname))
		if host == "" || seenHost[host] {
			return
		}
		seenHost[host] = true
		if n := seenName[name]; n > 0 {
			seenName[name] = n + 1
			name = name + "-" + strconv.Itoa(n+1)
		} else {
			seenName[name] = 1
		}
		servers = append(servers, server{
			Name:     name,
			Hostname: host,
			Country:  strings.ToUpper(e.Geo.CountryCode),
			City:     e.Geo.CityName,
		})
	}
	for _, e := range entries {
		cc := strings.ToLower(strings.TrimSpace(e.Geo.CountryCode))
		if len(cc) != 2 {
			continue
		}
		if len(e.Children) == 0 {
			name := cc
			if hasTag(e.Tags, "free") {
				name = cc + "-free"
			}
			add(e, name)
			continue
		}
		for _, c := range e.Children {
			ccc := strings.ToLower(strings.TrimSpace(c.Geo.CountryCode))
			if len(ccc) != 2 {
				ccc = cc
			}
			if c.Geo.CountryCode == "" {
				c.Geo.CountryCode = e.Geo.CountryCode
			}
			slug := slugify(c.DisplayName)
			if slug == "" {
				slug = slugify(c.Geo.CityName)
			}
			name := ccc
			if slug != "" {
				name = ccc + "-" + slug
			}
			add(c, name)
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers in the list")
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	return servers, nil
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// slugify lower-cases s and joins its runs of letters and digits with
// single hyphens: "Helsinki #1" -> "helsinki-1", "Washington, D.C." ->
// "washington-d-c". Letters outside ASCII are kept as they are.
func slugify(s string) string {
	var b strings.Builder
	pending := false
	for _, r := range strings.ToLower(s) {
		isWord := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r > 127
		if !isWord {
			pending = b.Len() > 0
			continue
		}
		if pending {
			b.WriteByte('-')
			pending = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// findServer returns the server named location (case-insensitive).
func findServer(servers []server, location string) (server, bool) {
	for _, s := range servers {
		if strings.EqualFold(s.Name, location) {
			return s, true
		}
	}
	return server{}, false
}
