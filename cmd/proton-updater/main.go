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
// Two modes:
//
//	(default) refresh mode — reuses a stored session and never triggers the
//	  CAPTCHA. Reads:
//	    PROTON_SESSION_UID            account UID from a prior login
//	    PROTON_SESSION_REFRESH_TOKEN  refresh token from a prior login
//	    PROTON_SESSION_OUT (optional) path to write the rotated session JSON
//	                                  ({uid, refresh_token}) for write-back
//	  and prints servers.json to stdout.
//
//	-login — one-time interactive seed. Performs the SRP password login and,
//	  when Proton challenges it, prints the verify.proton.me URL to solve the
//	  CAPTCHA in a browser; re-run with -hv-token <token>. On success it emits
//	  the reusable session {uid, refresh_token} (to PROTON_SESSION_OUT, else
//	  stdout) to store in OpenBao. Reads:
//	    PROTON_ACCOUNT_USERNAME  ProtonMail/ProtonVPN account email
//	    PROTON_ACCOUNT_PASSWORD  account login password (NOT the per-OpenVPN creds)
//	    PROTON_HV_TOKEN (optional) solved human-verification token to replay
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
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

// session is the reusable login state persisted in OpenBao between runs.
type session struct {
	UID          string `json:"uid"`
	RefreshToken string `json:"refresh_token"`
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("proton-updater: ")

	loginMode := flag.Bool("login", false,
		"one-time interactive login: perform SRP (solving the CAPTCHA via the printed verify URL) and emit a reusable session for OpenBao")
	hvToken := flag.String("hv-token", os.Getenv("PROTON_HV_TOKEN"),
		"solved human-verification token to replay a CAPTCHA-challenged login")
	hvType := flag.String("hv-type", "captcha", "human-verification token type")
	flag.Parse()

	ctx := context.Background()
	client, err := newAPIClient(ctx)
	if err != nil {
		log.Fatalf("api client init: %v", err)
	}

	if *loginMode {
		runLogin(ctx, client, *hvToken, *hvType)
		return
	}
	runRefresh(ctx, client)
}

// runRefresh is the default (CI) path: reuse a stored session to fetch the
// catalog without ever hitting the CAPTCHA-gated SRP login.
func runRefresh(ctx context.Context, client *apiClient) {
	uid := os.Getenv("PROTON_SESSION_UID")
	refreshToken := os.Getenv("PROTON_SESSION_REFRESH_TOKEN")
	if uid == "" || refreshToken == "" {
		log.Fatalf("PROTON_SESSION_UID and PROTON_SESSION_REFRESH_TOKEN must be set " +
			"(seed them once with `proton-updater -login`)")
	}

	cookie, rotated, err := client.refreshSession(ctx, uid, refreshToken)
	if err != nil {
		log.Fatalf("session refresh failed — re-seed with `proton-updater -login`: %v", err)
	}

	// Persist the (possibly rotated) refresh token so the next run can reuse
	// it. Written before the fetch so a later failure can't lose a rotation.
	if err := writeSession(session{UID: uid, RefreshToken: rotated}); err != nil {
		log.Fatalf("persisting rotated session: %v", err)
	}

	logicals, err := client.fetchLogicals(ctx, cookie)
	if err != nil {
		log.Fatalf("fetch logicals: %v", err)
	}
	emitServers(logicals)
}

// runLogin is the one-time seed: SRP login (with optional CAPTCHA replay),
// then emit the reusable session for the operator to store in OpenBao.
func runLogin(ctx context.Context, client *apiClient, hvToken, hvType string) {
	email := os.Getenv("PROTON_ACCOUNT_USERNAME")
	password := os.Getenv("PROTON_ACCOUNT_PASSWORD")
	if email == "" || password == "" {
		log.Fatalf("PROTON_ACCOUNT_USERNAME and PROTON_ACCOUNT_PASSWORD must be set for -login")
	}

	cookie, refreshToken, err := client.authenticate(ctx, email, password, hvToken, hvType)
	if err != nil {
		var apiErr *protonAPIError
		if errors.As(err, &apiErr) && apiErr.isHumanVerification() {
			fmt.Fprintf(os.Stderr,
				"\nProton requires a CAPTCHA. Solve it in a browser:\n  %s\n"+
					"then re-run from the SAME machine:\n  proton-updater -login -hv-token <token-from-that-page>\n\n",
				apiErr.verifyURL())
		}
		log.Fatalf("login: %v", err)
	}
	if refreshToken == "" {
		log.Fatalf("login succeeded but no refresh token returned — cannot seed a reusable session")
	}

	if err := writeSession(session{UID: cookie.uid, RefreshToken: refreshToken}); err != nil {
		log.Fatalf("writing session: %v", err)
	}
	fmt.Fprintf(os.Stderr,
		"proton-updater: login OK — store the emitted {uid, refresh_token} in OpenBao "+
			"at lpellegr/kv/vpn/proton-session\n")
}

// writeSession emits the session JSON to PROTON_SESSION_OUT (0600) when set,
// otherwise to stdout (so an interactive -login can be piped/copied).
func writeSession(s session) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if path := os.Getenv("PROTON_SESSION_OUT"); path != "" {
		return os.WriteFile(path, b, 0o600)
	}
	_, err = os.Stdout.Write(append(b, '\n'))
	return err
}

// emitServers transforms, sorts and prints the logicals catalog to stdout.
func emitServers(logicals *logicalsResponse) {
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
