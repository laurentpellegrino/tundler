package manager

import (
	"context"
	"math/rand"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

// -----------------------------------------------------------------------------
// Manager (stateless)
// -----------------------------------------------------------------------------

type Manager struct {
	providers map[string]provider.VPNProvider
}

func New(debug bool) *Manager {
	shared.SetDebug(debug)
	return &Manager{providers: provider.Registry}
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

// Connect tears down any active tunnel, then connects via:
//   - the requested *provider* (when non-empty) with optional *location*, or
//   - a random logged-in provider. Empty strings mean “unspecified”.
func (m *Manager) Connect(ctx context.Context, providerName, location string) (provider.Status, error) {
	if _, p := m.connectedProvider(ctx); p != nil { // disconnect current tunnel
		_ = p.Disconnect(ctx)
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
		locs := p.Locations(ctx)
		if len(locs) > 0 {
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			location = locs[r.Intn(len(locs))]
		}
	}

	return p.Connect(ctx, location), nil
}

// Disconnect terminates any active tunnel.
func (m *Manager) Disconnect(ctx context.Context) error {
	if _, p := m.connectedProvider(ctx); p != nil {
		return p.Disconnect(ctx)
	}
	return nil
}

// List returns every provider with its version and login state.
func (m *Manager) List(ctx context.Context) map[string]any {
	return map[string]any{"providers": m.providerInfos(ctx)}
}

// Login authenticates one provider (name ≠ "") or all providers (name == "").
func (m *Manager) Login(ctx context.Context, name string) error {
	if name != "" {
		p, ok := m.providers[name]
		if !ok {
			return shared.ErrUnknownProvider
		}
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
		if err := m.providers[n].Logout(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Status reports VPN status.
func (m *Manager) Status(ctx context.Context) (provider.Status, error) {
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
