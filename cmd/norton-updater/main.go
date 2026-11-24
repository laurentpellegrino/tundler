// norton-updater fetches the SurfEasy discovery catalog and prints a
// servers.json to stdout: the exact []Server shape the norton provider reads
// (ip, country, city, location_key). It is meant to be run by a scheduled
// workflow that publishes the result as the `norton-servers` release asset,
// baked into the image at /etc/norton/servers.json — the same split tundler
// uses for proton/cyberghost, keeping all authenticated API calls OUT of the
// runtime tunnel binary.
//
// The catalog is the Avast/SurfEasy backend behind Norton VPN:
//
//	GET https://api.se-platform.com/discovery/v12/geos            -> countries
//	GET https://api.se-platform.com/discovery/v9/discover?location_key=<cc> -> servers
//
// with headers SE-Client-API-Key (the product id), SE-Client-Type, Version,
// Locale and an Authorization: Bearer <JWT>.
//
// Reads:
//
//	NORTON_DISCOVERY_TOKEN       Bearer JWT for the SurfEasy API (optional; if
//	                             empty, a fresh one is minted via the cloudconnect
//	                             silent refresh — see refresh.go)
//	NORTON_SE_API_KEY            SE-Client-API-Key (product id); defaults to the
//	                             baked nlk401 product key
//	NORTON_DISCOVERY_COUNTRIES   optional CSV of ISO country codes to limit to
//	                             (default: every country the catalog lists)
//
// Token lifecycle: the discovery JWT is short-lived (~12h). The backend's renew
// endpoint is a dead end, but the cloudconnect silent refresh mints a fresh JWT
// from the static device-identity + license ids with no sign-in, no session and
// no seat use (refresh.go), so a scheduled job runs unattended. The runtime
// tunnel needs NO token — it only reads the baked servers.json plus its device
// credential.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	apiBase          = "https://api.se-platform.com"
	clientType       = "nlk401"
	clientVersion    = "26.20.0.261030325"
	clientLocale     = "en-US"
	defaultProductID = "D11C728A8AAA2898BF367C5212E4CD7D17AC7F742119927A49980F08B39E35C5"
)

// Server mirrors the norton provider's exit record (internal/provider/norton).
type Server struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	City        string `json:"city"`
	LocationKey string `json:"location_key"`
}

type client struct {
	http   *http.Client
	token  string
	apiKey string
}

func (c *client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("SE-Client-API-Key", c.apiKey)
	req.Header.Set("SE-Client-Type", clientType)
	req.Header.Set("SE-Client-Version", clientVersion)
	req.Header.Set("SE-Client-Locale", clientLocale)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("GET %s: decode: %w", path, err)
	}
	return nil
}

// geos returns the country-level location keys from /discovery/v12/geos.
func (c *client) geos(ctx context.Context) ([]string, error) {
	var out struct {
		Status struct {
			Code int `json:"code"`
		} `json:"status"`
		Data struct {
			Geos []struct {
				CountryCode string `json:"country_code"`
				LocationKey string `json:"location_key"`
			} `json:"geos"`
		} `json:"data"`
	}
	if err := c.get(ctx, "/discovery/v12/geos", &out); err != nil {
		return nil, err
	}
	if out.Status.Code != 0 {
		return nil, fmt.Errorf("geos: status code %d", out.Status.Code)
	}
	var keys []string
	for _, g := range out.Data.Geos {
		if k := strings.TrimSpace(g.LocationKey); k != "" {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// discover returns the OpenVPN servers for one location key.
func (c *client) discover(ctx context.Context, locationKey string) ([]Server, error) {
	var out struct {
		Data struct {
			IPs []struct {
				IP       string `json:"ip"`
				Protocol string `json:"protocol"`
				Geo      struct {
					CountryCode string `json:"country_code"`
					City        string `json:"city"`
					LocationKey string `json:"location_key"`
				} `json:"geo"`
			} `json:"ips"`
		} `json:"data"`
	}
	if err := c.get(ctx, "/discovery/v9/discover?location_key="+url.QueryEscape(locationKey), &out); err != nil {
		return nil, err
	}
	var servers []Server
	for _, i := range out.Data.IPs {
		if i.Protocol != "openvpn" || i.IP == "" {
			continue
		}
		servers = append(servers, Server{
			IP:          i.IP,
			Country:     i.Geo.CountryCode,
			City:        i.Geo.City,
			LocationKey: i.Geo.LocationKey,
		})
	}
	return servers, nil
}

func main() {
	log.SetFlags(0)
	apiKey := os.Getenv("NORTON_SE_API_KEY")
	if strings.TrimSpace(apiKey) == "" {
		apiKey = defaultProductID
	}
	only := map[string]bool{}
	for _, cc := range strings.Split(os.Getenv("NORTON_DISCOVERY_COUNTRIES"), ",") {
		if cc = strings.ToUpper(strings.TrimSpace(cc)); cc != "" {
			only[cc] = true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Force HTTP/1.1. The cloudconnect silent-refresh endpoint rejects the request
	// body with a JsonEncodingError when the call is made over HTTP/2 (which Go
	// negotiates by default); the app and a plain HTTP/1.1 client are accepted.
	hc := &http.Client{Timeout: 30 * time.Second}

	// The discovery API needs a short-lived Bearer JWT. Prefer a pre-seeded one
	// (NORTON_DISCOVERY_TOKEN); otherwise mint a fresh one headlessly via the
	// cloudconnect silent refresh (refresh.go) so a scheduled job can run
	// unattended.
	token := strings.TrimSpace(os.Getenv("NORTON_DISCOVERY_TOKEN"))
	if token == "" {
		t, err := refreshDiscoveryToken(ctx, hc)
		if err != nil {
			log.Fatalf("mint discovery token: %v", err)
		}
		token = t
		log.Printf("norton-updater: minted a fresh discovery token via silent refresh (len %d)", len(token))
	}
	c := &client{http: hc, token: token, apiKey: apiKey}

	keys, err := c.geos(ctx)
	if err != nil {
		log.Fatalf("fetch geos: %v", err)
	}
	if len(keys) == 0 {
		log.Fatal("geos returned no countries")
	}

	seen := map[string]bool{}
	var servers []Server
	var failures []string
	for _, k := range keys {
		if len(only) > 0 && !only[strings.ToUpper(k)] {
			continue
		}
		found, err := c.discover(ctx, k)
		if err != nil {
			failures = append(failures, k)
			continue
		}
		for _, s := range found {
			if s.IP == "" || seen[s.IP] {
				continue
			}
			seen[s.IP] = true
			servers = append(servers, s)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if len(servers) == 0 {
		log.Fatal("discovery produced no OpenVPN servers (token expired or rejected?)")
	}
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Country != servers[j].Country {
			return servers[i].Country < servers[j].Country
		}
		if servers[i].City != servers[j].City {
			return servers[i].City < servers[j].City
		}
		return servers[i].IP < servers[j].IP
	})

	ccs := map[string]bool{}
	for _, s := range servers {
		ccs[s.Country] = true
	}
	log.Printf("norton-updater: %d OpenVPN servers across %d countries (%d discover failures)", len(servers), len(ccs), len(failures))

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(servers); err != nil {
		log.Fatalf("encode: %v", err)
	}
}
