// Package provider defines the minimal abstraction layer required by tundler
// to control multiple VPN command-line clients through a uniform API.
package provider

import "context"

// Status is the neutral connection state returned to the HTTP layer.
//
//   - Connected – true when the VPN tunnel is up.
//   - IP        – the public IPv4 address observed via the provider (optional).
//   - Provider  – provider identifier (optional, filled by Manager).
type Status struct {
	Connected bool   `json:"connected"`
	IP        string `json:"ip,omitempty"`
	Location  string `json:"location,omitempty"`
	Provider  string `json:"provider,omitempty"`
}

// VPNProvider is the contract every CLI wrapper (ExpressVPN, NordVPN, …)
// must satisfy.
//
// Every method MUST be idempotent and MUST run synchronously, i.e. it must
// return only after the CLI command has finished.
//
// Context cancellation should be honoured whenever the underlying CLI
// supports it; otherwise the implementation may ignore ctx.
//
// Behavioural notes:
//
//   - Login / Logout authenticate the CLI; they do NOT connect/disconnect
//     a tunnel.
//
//   - Connect must start a tunnel (or switch location) and immediately
//     return the resulting Status. An empty *location* means “provider default”.
type VPNProvider interface {
	// ActiveLocation returns the location the tunnel is currently using
	// (empty when disconnected)
	ActiveLocation(ctx context.Context) string

	// Connect starts or switches a VPN tunnel.
	Connect(ctx context.Context, location string) Status

	// Connected reports whether a tunnel is currently up.
	Connected(ctx context.Context) bool

	// Disconnect tears down the VPN tunnel (no-op if not connected).
	Disconnect(ctx context.Context) error

	// Locations returns the list of locations understood by the CLI.
	Locations(ctx context.Context) []string

	// LoggedIn reports whether the CLI is authenticated.
	LoggedIn(ctx context.Context) bool

	// Login authenticates the CLI (using environment variables, keychain, …).
	Login(ctx context.Context) error

	// Logout clears credentials (must NOT fail if already logged out).
	Logout(ctx context.Context) error

	// Status returns the current connection status (even if disconnected).
	Status(ctx context.Context) Status

	// Version returns the semantic version string of the CLI/daemon.
	Version(ctx context.Context) (string, error)
}

// Registry is filled at init() time by each provider package so that Manager
// can discover all compiled-in providers at runtime.
var Registry = map[string]VPNProvider{}
