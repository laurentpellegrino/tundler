package manager

import (
	"context"
	"math/rand"
	"sort"
	"time"

	"github.com/laurentpellegrino/tundler/internal/plugin"
	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
	"github.com/laurentpellegrino/tundler/internal/telemetry"
)

// -----------------------------------------------------------------------------
// Manager (stateless)
// -----------------------------------------------------------------------------

// LocationFilter is the per-provider allow/block policy applied to random
// location selection. Allow narrows the candidate pool (empty means "use the
// provider's full list"); Block subtracts entries from whatever pool was
// chosen.
type LocationFilter struct {
	Allow []string
	Block []string
}

type Manager struct {
	filters   map[string]LocationFilter
	plugins   *plugin.Manager
	providers map[string]provider.VPNProvider
}

func New(debug bool, filters map[string]LocationFilter, plugins *plugin.Manager) *Manager {
	shared.SetDebug(debug)
	return &Manager{filters: filters, plugins: plugins, providers: provider.Registry}
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

// Connect tears down any active tunnel, then connects via:
//   - the requested *provider* (when non-empty) with optional *location*, or
//   - a random logged-in provider. Empty strings mean “unspecified”.
//
// allowLocations and blockLocations are per-request lists used only when
// location is empty:
//   - allowLocations, if non-empty, replaces the configured allow list as
//     the candidate pool (request beats config).
//   - blockLocations is unioned with the configured block list and
//     subtracted from whichever candidate pool is in effect.
//
// When location is non-empty (explicit pin) both lists are ignored.
func (m *Manager) Connect(ctx context.Context, providerName, location string, allowLocations, blockLocations []string) (provider.Status, error) {
	if _, p := m.connectedProvider(ctx); p != nil { // disconnect current tunnel
		st := p.Status(ctx)
		_ = p.Disconnect(ctx)
		if m.plugins != nil && st.Connected {
			m.plugins.Emit(ctx, "disconnected", st.Provider, st.Location, statusRegion(st), st.IP)
		}
	}

	var p provider.VPNProvider
	if providerName != "" {
		var ok bool
		p, ok = m.providers[providerName]
		if !ok {
			return provider.Status{}, shared.ErrUnknownProvider
		}
		if !p.LoggedIn(ctx) {
			return provider.Status{}, shared.ErrProviderNotLoggedIn
		}
	} else {
		var err error
		providerName, p, err = m.randomLoggedIn(ctx)
		if err != nil {
			return provider.Status{}, err
		}
	}

	if location == "" {
		f := m.filters[providerName]
		var locs []string
		switch {
		case len(allowLocations) > 0:
			locs = allowLocations
		case len(f.Allow) > 0:
			locs = f.Allow
		default:
			locs = p.Locations(ctx)
		}
		hasFilter := len(allowLocations) > 0 || len(f.Allow) > 0 ||
			len(f.Block) > 0 || len(blockLocations) > 0
		locs = dropMalformedLocations(locs)
		locs = filterOut(locs, f.Block)
		locs = filterOut(locs, blockLocations)
		if len(locs) > 0 {
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			location = locs[r.Intn(len(locs))]
		} else if hasFilter {
			return provider.Status{Provider: providerName}, shared.ErrNoEligibleLocations
		}
		// else: no filter configured and nothing to enumerate — fall through
		// with location="" so the provider can pick its own default.
	}

	shared.Debugf("[manager] connect %s location=%s", providerName, location)
	status := p.Connect(ctx, location)
	// Stamp the attempted provider/location onto every returned Status,
	// including failures. Without this, clients observing a connect that
	// returned Connected=false see {provider: "", location: ""} and have
	// no way to tell which provider is misbehaving.
	if status.Provider == "" {
		status.Provider = providerName
	}
	if status.Location == "" {
		status.Location = location
	}
	if status.Connected {
		// Lower the tunnel interface MTU when the underlay (pod eth0)
		// is smaller than the provider assumed — fixes nordlynx/wg
		// black-holing under Kubernetes CNIs that add encapsulation
		// overhead (Calico IP-in-IP, Cilium VXLAN, etc.). No-op when
		// the underlay is 1500 bytes, so plain Docker is unaffected.
		clampTunnelMTUIfNeeded(ctx)
		telemetry.TrackConnect(providerName, location, status.IP)
		if m.plugins != nil {
			m.plugins.Emit(ctx, "connected", providerName, location, statusRegion(status), status.IP)
		}
	}
	return status, nil
}

// Disconnect terminates any active tunnel.
func (m *Manager) Disconnect(ctx context.Context) error {
	if _, p := m.connectedProvider(ctx); p != nil {
		shared.Debugf("[manager] disconnect")
		st := p.Status(ctx)
		if err := p.Disconnect(ctx); err != nil {
			return err
		}
		if m.plugins != nil && st.Connected {
			m.plugins.Emit(ctx, "disconnected", st.Provider, st.Location, statusRegion(st), st.IP)
		}
		return nil
	}
	return nil
}

// List returns every provider with its version and login state.
func (m *Manager) List(ctx context.Context) map[string]any {
	shared.Debugf("[manager] list providers")
	return map[string]any{"providers": m.providerInfos(ctx)}
}

// Locations returns every provider with its supported locations sorted
// lexicographically.
func (m *Manager) Locations(ctx context.Context) map[string][]string {
	shared.Debugf("[manager] list locations")
	names := m.loggedInProviders(ctx)
	out := make(map[string][]string, len(names))
	for _, name := range names {
		p := m.providers[name]
		locs := append([]string(nil), p.Locations(ctx)...)
		sort.Strings(locs)
		out[name] = locs
	}
	return out
}

// Login authenticates one provider (name ≠ "") or all providers (name == "").
func (m *Manager) Login(ctx context.Context, name string) error {
	if name != "" {
		p, ok := m.providers[name]
		if !ok {
			return shared.ErrUnknownProvider
		}
		shared.Debugf("[manager] login %s", name)
		return p.Login(ctx)
	}

	var success bool
	for _, p := range m.providers {
		if err := p.Login(ctx); err == nil {
			success = true
		}
	}
	if !success {
		return shared.ErrNoLoggedInProviders
	}
	return nil
}

// Logout calls Logout on **logged-in providers only**.
//
//   - When *name* is given, it logs out that provider if and only if it is
//     logged in; otherwise it returns PROVIDER_NOT_LOGGED_IN.
//   - When *name* is empty, it logs out every logged-in provider; if none are
//     logged in it returns NO_LOGGED_IN_PROVIDERS.
func (m *Manager) Logout(ctx context.Context, name string) error {
	if name != "" {
		p, ok := m.providers[name]
		if !ok {
			return shared.ErrUnknownProvider
		}
		if !p.LoggedIn(ctx) {
			return shared.ErrProviderNotLoggedIn
		}
		return p.Logout(ctx)
	}

	names := m.loggedInProviders(ctx)
	if len(names) == 0 {
		return shared.ErrNoLoggedInProviders
	}

	var firstErr error
	for _, n := range names {
		shared.Debugf("[manager] logout %s", name)
		if err := m.providers[n].Logout(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Status reports VPN status.
func (m *Manager) Status(ctx context.Context) (provider.Status, error) {
	shared.Debugf("[manager] status")
	// If a tunnel is active, just return its status.
	if _, p := m.connectedProvider(ctx); p != nil {
		return p.Status(ctx), nil
	}

	// Otherwise look for a logged-in provider.
	if name, p := m.loggedInProvider(ctx); p != nil {
		st := p.Status(ctx)
		if st.Connected {
			st.Provider = name
		}
		return st, nil
	}

	return provider.Status{}, shared.ErrNoLoggedInProviders
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// connectedProviders returns names of providers with an active tunnel.
func (m *Manager) connectedProviders(ctx context.Context) []string {
	var out []string
	for name, p := range m.providers {
		if p.Connected(ctx) {
			out = append(out, name)
		}
	}
	return out
}

// loggedInProviders returns names of authenticated providers.
func (m *Manager) loggedInProviders(ctx context.Context) []string {
	var out []string
	for name, p := range m.providers {
		if p.LoggedIn(ctx) {
			out = append(out, name)
		}
	}
	return out
}

// connectedProvider – first provider with a live tunnel (if any).
func (m *Manager) connectedProvider(ctx context.Context) (string, provider.VPNProvider) {
	for _, name := range m.connectedProviders(ctx) {
		return name, m.providers[name]
	}
	return "", nil
}

// loggedInProvider – first provider that is logged in (if any).
func (m *Manager) loggedInProvider(ctx context.Context) (string, provider.VPNProvider) {
	for _, name := range m.loggedInProviders(ctx) {
		return name, m.providers[name]
	}
	return "", nil
}

// randomLoggedIn selects a random logged-in provider.
func (m *Manager) randomLoggedIn(ctx context.Context) (string, provider.VPNProvider, error) {
	names := m.loggedInProviders(ctx)
	if len(names) == 0 {
		return "", nil, shared.ErrNoLoggedInProviders
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	name := names[r.Intn(len(names))]
	return name, m.providers[name], nil
}

// providerInfos returns name → {logged_in, version}.
func (m *Manager) providerInfos(ctx context.Context) map[string]map[string]any {
	out := make(map[string]map[string]any, len(m.providers))
	for name, p := range m.providers {
		v, err := p.Version(ctx)
		if err != nil {
			v = "unknown"
		}
		out[name] = map[string]any{
			"logged_in": p.LoggedIn(ctx),
			"version":   v,
		}
	}
	return out
}

func statusRegion(st provider.Status) string {
	if st.Region != "" {
		return st.Region
	}
	return st.Location
}

// filterOut returns the entries of in that are not present in blocked.
// Comparison is exact (case-sensitive) to match how configured allow lists
// are validated against provider-supplied location names.
func filterOut(in, blocked []string) []string {
	if len(blocked) == 0 || len(in) == 0 {
		return in
	}
	deny := make(map[string]struct{}, len(blocked))
	for _, b := range blocked {
		deny[b] = struct{}{}
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, bad := deny[v]; !bad {
			out = append(out, v)
		}
	}
	return out
}

// dropMalformedLocations is a defence in depth against provider implementations
// that swallow CLI errors and return error text as if it were a location list.
// We can't validate location names structurally because the legitimate set is
// wildly heterogeneous across providers — hyphens (express: "uk-london",
// "usa-st.-louis"), underscores (nord/surfshark: "Cayman_Islands"), spaces
// (proton: "Costa Rica"), apostrophes (proton: "Cote d'Ivoire"), parens and
// dots (express: "india-(via-singapore)", "usa-st.-louis"). The one shape no
// real location takes is a *purely numeric* token: those only show up when
// CLI error output ("Timed out after 5.002 sec") gets fed through
// strings.Fields and the digits leak in as "5.002". Empty strings are
// dropped on the same principle — they only appear from over-eager parsing.
// Anything else passes through; we trust the provider beyond that.
func dropMalformedLocations(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:0:0]
	for _, v := range in {
		if v == "" || isPurelyNumeric(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func isPurelyNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}
