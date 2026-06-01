// Package mullvad drives Mullvad over WireGuard directly via wg-quick,
// using PRE-GENERATED per-pod keys instead of the Mullvad daemon.
//
// Why not the official client: the mullvad CLI/daemon generates and
// manages its OWN WireGuard key per device and caps an account at 5
// devices; its only "too many devices" recovery is revoke-ALL, which is
// mutually destructive across a fleet (each pod's login nukes the others'
// devices). For a multi-tunnel deployment that thrashes.
//
// This provider instead pins ONE pre-registered WireGuard key per pod
// ordinal (POD_<n>_MULLVAD_*), so the 5 devices map 1:1 to the 5 pods and
// never churn. Mullvad assigns each key a fixed internal tunnel address
// (the [Interface] Address) which MUST be used or the handshake completes
// but no return traffic routes — so the key AND its assigned address are
// both sourced from OpenBao (vpn/mullvad/pod-<n> {key,address,address6}).
//
// The public EXIT IP is the relay's, not the key's: the same key works on
// any relay, so exit-IP diversity comes from rotating the [Peer] (relay
// public key + endpoint) picked from Mullvad's public relay list. No
// daemon, no account login — same shape as the surfshark WireGuard path.
package mullvad

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	name = "mullvad"
	// relaysFile is the trimmed Mullvad WireGuard relay list baked into
	// the image at build time (docker/providers/mullvad/install.sh
	// downloads it from the `mullvad-relays` GH release, refreshed daily
	// by .github/workflows/update-mullvad-relays.yml). Read from disk at
	// runtime — no per-pod dependency on Mullvad's API.
	relaysFile   = "/etc/mullvad/relays.json"
	wgConfigPath = "/etc/mullvad/wireguard/wg0.conf"
	wgPort       = "51820"
	// mullvadDNS is Mullvad's in-tunnel resolver (the WireGuard
	// ipv4_gateway). Using it keeps DNS inside the tunnel.
	mullvadDNS = "10.64.0.1"
)

type Mullvad struct{}

// relay is one Mullvad WireGuard server: its peer public key + endpoint
// (which set the exit IP) plus the country/city resolved from the relay
// list's locations map (for Locations()/EXCLUDED_LOCATIONS matching).
type relay struct {
	Hostname   string
	Location   string // e.g. "se-got"
	Country    string
	City       string
	IPv4AddrIn string // endpoint IP
	PublicKey  string // peer public key
}

// JSON shape of https://api.mullvad.net/app/v1/relays (subset).
type relaysResponse struct {
	Locations map[string]struct {
		Country string `json:"country"`
		City    string `json:"city"`
	} `json:"locations"`
	Wireguard struct {
		Relays []struct {
			Hostname   string `json:"hostname"`
			Active     bool   `json:"active"`
			Location   string `json:"location"`
			IPv4AddrIn string `json:"ipv4_addr_in"`
			PublicKey  string `json:"public_key"`
		} `json:"relays"`
	} `json:"wireguard"`
}

var (
	relayCache     []relay
	relayCacheMu   sync.RWMutex
	activeRelay    *relay
	activeLocation string
	activeMu       sync.RWMutex
	loggedIn       bool

	// Extracts the ordinal suffix from a StatefulSet pod name (e.g.
	// tundler-tunnel-mullvad-3 → 3) so each pod reads only its own
	// POD_<ordinal>_MULLVAD_* WireGuard identity.
	podOrdinalRe = regexp.MustCompile(`-(\d+)$`)
)

func init() { provider.Registry[name] = Mullvad{} }

// podOrdinal extracts this pod's ordinal from POD_NAME (downward API).
// Returns 0 when POD_NAME is unset (local-dev fallback).
func podOrdinal() int {
	pod := os.Getenv("POD_NAME")
	if pod == "" {
		return 0
	}
	if m := podOrdinalRe.FindStringSubmatch(pod); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n
		}
	}
	return 0
}

// wgIdentity returns this pod's WireGuard private key and the [Interface]
// Address line (Mullvad's assigned internal address for that key). v1
// routes IPv4 only — POD_<n>_MULLVAD_ADDRESS6 is provisioned in the
// secret for a future dual-stack flip but is not used here (a v4-only
// tunnel still reaches ipinfo for both the v4 and v6 crawlers).
func wgIdentity() (privKey, address string, err error) {
	ord := podOrdinal()
	prefix := fmt.Sprintf("POD_%d_MULLVAD_", ord)
	privKey = strings.TrimSpace(os.Getenv(prefix + "PRIVATE_KEY"))
	address = strings.TrimSpace(os.Getenv(prefix + "ADDRESS"))
	if privKey == "" || address == "" {
		return "", "", fmt.Errorf(
			"missing Mullvad WireGuard identity for pod ordinal %d (need %sPRIVATE_KEY, %sADDRESS)",
			ord, prefix, prefix)
	}
	return privKey, address, nil
}

// loadRelays parses the baked relay list (relaysFile) into the active
// WireGuard relays, caching the result for the process lifetime (the file
// is static — refreshed only by an image rebuild). Country/city are
// resolved from the file's locations map.
func loadRelays() ([]relay, error) {
	relayCacheMu.RLock()
	if len(relayCache) > 0 {
		cached := relayCache
		relayCacheMu.RUnlock()
		return cached, nil
	}
	relayCacheMu.RUnlock()

	relayCacheMu.Lock()
	defer relayCacheMu.Unlock()
	if len(relayCache) > 0 {
		return relayCache, nil
	}

	data, err := os.ReadFile(relaysFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", relaysFile, err)
	}
	var parsed relaysResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse %s: %w", relaysFile, err)
	}

	var relays []relay
	for _, r := range parsed.Wireguard.Relays {
		if !r.Active || r.IPv4AddrIn == "" || r.PublicKey == "" {
			continue
		}
		loc := parsed.Locations[r.Location]
		relays = append(relays, relay{
			Hostname:   r.Hostname,
			Location:   r.Location,
			Country:    loc.Country,
			City:       loc.City,
			IPv4AddrIn: r.IPv4AddrIn,
			PublicKey:  r.PublicKey,
		})
	}
	if len(relays) == 0 {
		return nil, fmt.Errorf("no active Mullvad WireGuard relays in %s", relaysFile)
	}

	relayCache = relays
	shared.Debugf("Mullvad: loaded %d WireGuard relays from %s", len(relays), relaysFile)
	return relays, nil
}

// findRelays filters relays by a location string matched against country
// name, the location code (e.g. "se-got"), or city — case-insensitive.
// Empty location returns all.
func findRelays(relays []relay, location string) []relay {
	if location == "" {
		return relays
	}
	want := strings.ToLower(location)
	var matches []relay
	for _, r := range relays {
		if strings.ToLower(r.Country) == want ||
			strings.ToLower(r.Location) == want ||
			strings.ToLower(r.City) == want {
			matches = append(matches, r)
		}
	}
	return matches
}

func pickRandomRelay(relays []relay) *relay {
	if len(relays) == 0 {
		return nil
	}
	r := relays[rand.Intn(len(relays))]
	return &r
}

func (m Mullvad) ActiveLocation(ctx context.Context) string {
	if activeRelay == nil {
		return ""
	}
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeLocation
}

func (m Mullvad) Connect(ctx context.Context, location string) provider.Status {
	privKey, address, err := wgIdentity()
	if err != nil {
		shared.Debugf("Mullvad: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}

	relays, err := loadRelays()
	if err != nil {
		shared.Debugf("Mullvad: failed to fetch relays: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	matches := findRelays(relays, location)
	if len(matches) == 0 {
		shared.Debugf("Mullvad: no relays for location: %s", location)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}
	server := pickRandomRelay(matches)

	// The exit IP is set by the relay (Peer), not the key — so the same
	// pinned key produces a fresh exit IP on every rotation to a new relay.
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s:%s
PersistentKeepalive = 25
`, privKey, address, mullvadDNS, server.PublicKey, server.IPv4AddrIn, wgPort)

	if err := os.WriteFile(wgConfigPath, []byte(config), 0600); err != nil {
		shared.Debugf("Mullvad: failed to write config: %v", err)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	// wg0 is brought up in the MAIN network namespace (NOT vpnns) — the
	// in-process CONNECT proxy lives in main ns and dials upstream with a
	// plain net.DialTimeout (no fwmark), so wg0 must be the main-ns
	// default route. RunCmd (post-2026-05-28 default) skips the
	// `ip netns exec vpnns` wrap. Same model as the surfshark WireGuard
	// path. Tear down any leftover wg0 first: the service restarts in the
	// same pod/netns, so a wg0 from a prior attempt survives and would
	// abort `wg-quick up` with "wg0 already exists" → crashloop.
	cleanupStaleWireGuard(ctx, wgConfigPath)

	if out, err := shared.RunCmd(ctx, "wg-quick", "up", wgConfigPath); err != nil {
		shared.Debugf("Mullvad: wg-quick up failed: %v: %s", err, out)
		return provider.Status{Connected: false, Provider: name, Location: location}
	}

	activeRelay = server
	activeMu.Lock()
	activeLocation = location
	activeMu.Unlock()
	return m.Status(ctx)
}

func (m Mullvad) Connected(ctx context.Context) bool {
	return isWireGuardConnected()
}

func (m Mullvad) Disconnect(ctx context.Context) error {
	// wg-quick down must run in the same namespace `up` ran (main ns),
	// else it no-ops against vpnns and leaks wg0 + its policy rules.
	shared.RunCmd(ctx, "wg-quick", "down", wgConfigPath)
	activeRelay = nil
	activeMu.Lock()
	activeLocation = ""
	activeMu.Unlock()
	return nil
}

func (m Mullvad) Locations(ctx context.Context) []string {
	relays, err := loadRelays()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var locations []string
	for _, r := range relays {
		if r.Country == "" || seen[r.Country] {
			continue
		}
		seen[r.Country] = true
		locations = append(locations, r.Country)
	}
	return locations
}

func (m Mullvad) LoggedIn(ctx context.Context) bool { return loggedIn }

// Login is a no-op handshake for this provider — there is no account
// login, just a check that this pod's WireGuard identity is present. The
// device is pre-registered out of band; the key + assigned address come
// from the secret.
func (m Mullvad) Login(ctx context.Context) error {
	if _, _, err := wgIdentity(); err != nil {
		return err
	}
	loggedIn = true
	return nil
}

func (m Mullvad) Logout(ctx context.Context) error {
	loggedIn = false
	return nil
}

func (m Mullvad) Status(ctx context.Context) provider.Status {
	if !isWireGuardConnected() {
		return provider.Status{Connected: false, Provider: name}
	}
	status := provider.Status{
		Connected: true,
		Location:  m.ActiveLocation(ctx),
		Region:    activeRegion(),
		Provider:  name,
	}
	if out, err := shared.RunCmd(ctx, "curl", "-s", "--max-time", "5", "https://icanhazip.com"); err == nil {
		status.IP = strings.TrimSpace(out)
	}
	return status
}

func activeRegion() string {
	if activeRelay == nil {
		return ""
	}
	if activeRelay.City != "" {
		return activeRelay.Country + " - " + activeRelay.City
	}
	return activeRelay.Country
}

func (m Mullvad) Version(ctx context.Context) (string, error) {
	relays, err := loadRelays()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("wireguard (%d relays)", len(relays)), nil
}

// cleanupStaleWireGuard best-effort removes a leftover wg0 before a fresh
// `wg-quick up`. No-op on the happy path; all errors ignored.
func cleanupStaleWireGuard(ctx context.Context, configFile string) {
	if !wireGuardInterfacePresent(ctx) {
		return
	}
	shared.Debugf("Mullvad: stale wg0 from a prior run — tearing down before up")
	shared.RunCmdSilent(ctx, "wg-quick", "down", configFile)
	shared.RunCmdSilent(ctx, "ip", "link", "del", "wg0")
}

func wireGuardInterfacePresent(ctx context.Context) bool {
	_, err := shared.RunCmdSilent(ctx, "ip", "link", "show", "wg0")
	return err == nil
}

// isWireGuardConnected reports whether wg0 is up in the main namespace.
func isWireGuardConnected() bool {
	out, err := shared.RunCmd(context.Background(), "wg", "show", "wg0")
	if err != nil {
		return false
	}
	return len(out) > 0
}
