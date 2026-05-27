// proton-updater authenticates against ProtonVPN's account API using
// SRP v4 and writes the current /vpn/v1/logicals server list to
// stdout. The output schema matches the file the protonvpn provider
// embeds at build time:
//
//	{"protonvpn": {"servers": [{vpn,country,region,city,server_name,
//	                            hostname,tcp,udp,ips}, ...]}}
//
// Designed to be invoked by a daily GitHub Actions workflow that
// commits the resulting servers.json into the tundler repo so the
// per-tunnel image bakes it in via go:embed. We deliberately keep all
// SRP / authenticated-API code OUT of the runtime tunnel binary —
// the tunnel only needs static server data plus the (separate)
// PROTON_OPENVPN_* credentials to dial OpenVPN.
//
// Required env:
//
//	PROTON_ACCOUNT_USERNAME  ProtonMail/ProtonVPN account email
//	PROTON_ACCOUNT_PASSWORD  account login password (NOT the
//	                         per-OpenVPN credentials)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

// outputServer is the JSON shape the tunnel-side provider parses.
// `features` is the Proton API's Features bitfield, propagated so
// the runtime can filter the catalog to a subset (e.g. SecureCore
// only, when ipinfo.io's blanket-block on Proton's commodity exit
// IPs makes the default tier unusable). Bit layout per Proton:
//
//	1 = SecureCore
//	2 = Tor
//	4 = P2P
//	8 = Stream
type outputServer struct {
	VPN        string   `json:"vpn"`
	Country    string   `json:"country"`
	Region     string   `json:"region"`
	City       string   `json:"city"`
	ServerName string   `json:"server_name"`
	Hostname   string   `json:"hostname"`
	TCP        bool     `json:"tcp"`
	UDP        bool     `json:"udp"`
	IPs        []string `json:"ips"`
	Features   int      `json:"features"`
	Tier       int      `json:"tier"`
}

type outputFile struct {
	ProtonVPN struct {
		Servers []outputServer `json:"servers"`
	} `json:"protonvpn"`
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("proton-updater: ")

	email := os.Getenv("PROTON_ACCOUNT_USERNAME")
	password := os.Getenv("PROTON_ACCOUNT_PASSWORD")
	if email == "" || password == "" {
		log.Fatalf("PROTON_ACCOUNT_USERNAME and PROTON_ACCOUNT_PASSWORD must be set")
	}

	ctx := context.Background()
	client, err := newAPIClient(ctx)
	if err != nil {
		log.Fatalf("api client init: %v", err)
	}
	cookie, err := client.authenticate(ctx, email, password)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	logicals, err := client.fetchLogicals(ctx, cookie)
	if err != nil {
		log.Fatalf("fetch logicals: %v", err)
	}

	servers := transform(logicals)
	if len(servers) == 0 {
		log.Fatalf("logicals returned 0 usable servers — refusing to overwrite")
	}

	// Sort for stable diffs across daily runs: any reordering on
	// Proton's side then doesn't churn the git history.
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Country != servers[j].Country {
			return servers[i].Country < servers[j].Country
		}
		if servers[i].City != servers[j].City {
			return servers[i].City < servers[j].City
		}
		return servers[i].Hostname < servers[j].Hostname
	})

	var out outputFile
	out.ProtonVPN.Servers = servers

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&out); err != nil {
		log.Fatalf("encode: %v", err)
	}
	fmt.Fprintf(os.Stderr, "proton-updater: emitted %d servers across %d countries\n",
		len(servers), countCountries(servers))
}

func countCountries(servers []outputServer) int {
	seen := map[string]struct{}{}
	for _, s := range servers {
		seen[s.Country] = struct{}{}
	}
	return len(seen)
}

// transform fans a Proton logical-server entry into one outputServer
// per healthy physical server. Filters servers with status=0
// (disabled) and ones missing a hostname/entry-IP. The OpenVPN
// runtime path on the tunnel side selects randomly across these.
func transform(data *logicalsResponse) []outputServer {
	out := make([]outputServer, 0, len(data.LogicalServers)*2)
	for _, ls := range data.LogicalServers {
		// Both TCP and UDP work for ProtonVPN OpenVPN; the runtime
		// picks ports based on PROTON_OPENVPN_PROTOCOL. We emit
		// each physical server with tcp=true udp=true so the
		// existing protocol filter in protonvpn.go has both to
		// choose from.
		country := strings.TrimSpace(ls.ExitCountry)
		if country == "" {
			country = strings.TrimSpace(ls.Country)
		}
		region := strings.TrimSpace(ls.Region)
		city := strings.TrimSpace(ls.City)
		logicalName := strings.TrimSpace(ls.Name)

		tier := 0
		if ls.Tier != nil {
			tier = *ls.Tier
		}
		for _, ps := range ls.Servers {
			if ps.Status == 0 {
				continue // disabled — skip
			}
			host := strings.TrimSpace(ps.Domain)
			ip := strings.TrimSpace(ps.EntryIP)
			if host == "" && ip == "" {
				continue
			}
			ips := []string(nil)
			if ip != "" {
				ips = []string{ip}
			}
			out = append(out, outputServer{
				VPN:        "openvpn",
				Country:    country,
				Region:     region,
				City:       city,
				ServerName: logicalName,
				Hostname:   host,
				TCP:        true,
				UDP:        true,
				IPs:        ips,
				Features:   ls.Features,
				Tier:       tier,
			})
		}
	}
	return out
}
