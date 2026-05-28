// Package warp wraps the Cloudflare WARP consumer client as a
// tundler VPNProvider.
//
// WARP is conceptually different from the OpenVPN/WireGuard-based
// providers we already support: it's a Cloudflare-operated network
// that anonymises consumer traffic through Cloudflare's edge, with
// no user-facing concept of "country" or "server". A registration
// is anonymous and free; every CONNECT goes out a Cloudflare IP
// belonging to the colo geographically closest to the source.
//
// To fit into the existing tundler-tunnel slot+rotation
// architecture, we expose WARP as a single-location provider
// (Locations() returns just "auto") and rotate exit IPs by
// deleting + re-registering on each Disconnect. A fresh
// registration usually lands on a fresh edge IP, giving the
// rotator the per-cycle IP-change semantics it expects.
//
// Why "auto" is the single location:
//
//   - Cloudflare's consumer WARP does not let the user choose a
//     colo on the free tier. WARP+ (paid Zero Trust) supports
//     country-pinning via `warp-cli set-mode warp+doh` + region
//     hints, but we run anonymous registrations and that path
//     isn't available.
//
//   - The tundler-tunnel location picker only needs a non-empty
//     slice to feed Connect() with. A sentinel "auto" satisfies
//     that contract without lying about what we control.
package warp

import (
	"context"
	"strings"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const (
	bin  = "warp-cli"
	name = "warp"
)

// flags shared by every warp-cli invocation. --accept-tos
// suppresses the interactive TOS prompt that otherwise blocks
// every command on a fresh install.
var baseFlags = []string{"--accept-tos"}

func init() { provider.Registry[name] = WARP{} }

type WARP struct{}

func runCli(ctx context.Context, args ...string) (string, error) {
	return shared.RunCmd(ctx, bin, append(baseFlags, args...)...)
}

// LoggedIn returns true if warp-cli has an active anonymous
// registration with Cloudflare's backend.
func (w WARP) LoggedIn(ctx context.Context) bool {
	out, err := runCli(ctx, "registration", "show")
	if err != nil {
		return false
	}
	// `registration show` prints "Missing registration" (or empty
	// output on some versions) when nothing is registered. A live
	// registration prints a `Device ID` line.
	low := strings.ToLower(out)
	if strings.Contains(low, "missing") || strings.Contains(low, "not registered") {
		return false
	}
	return strings.Contains(low, "device id") || strings.Contains(low, "account")
}

// Login creates an anonymous registration (free tier). Idempotent.
func (w WARP) Login(ctx context.Context) error {
	if w.LoggedIn(ctx) {
		return nil
	}
	_, err := runCli(ctx, "registration", "new")
	return err
}

// Logout deletes the registration. Called from Disconnect() so the
// next Connect() gets a fresh anonymous identity (and usually a
// fresh edge IP) — that's how we satisfy the rotation contract.
func (w WARP) Logout(ctx context.Context) error {
	_, _ = runCli(ctx, "registration", "delete")
	return nil
}

// Connect brings the WARP tunnel up. The `location` argument is
// accepted to match the VPNProvider contract but ignored — see the
// package doc for why.
func (w WARP) Connect(ctx context.Context, location string) provider.Status {
	if !w.LoggedIn(ctx) {
		if err := w.Login(ctx); err != nil {
			shared.Debugf("WARP: Login() failed: %v", err)
			return provider.Status{Connected: false, Provider: name}
		}
	}
	// Mode `warp` is the consumer-tunnel mode (vs. `warp+doh`,
	// `doh` only, `off`, …). Setting it explicitly is harmless
	// when already in that mode.
	_, _ = runCli(ctx, "mode", "warp")
	if _, err := runCli(ctx, "connect"); err != nil {
		shared.Debugf("WARP: connect failed: %v", err)
		return provider.Status{Connected: false, Provider: name}
	}
	// Poll cloudflare's trace endpoint until `warp=on` appears.
	// This is the only signal that the tunnel is actually
	// routing — `warp-cli status` reports "Connected" a moment
	// before traffic actually flows.
	for i := 0; i < 60; i++ {
		if w.Connected(ctx) {
			return w.Status(ctx)
		}
		time.Sleep(500 * time.Millisecond)
	}
	shared.Debugf("WARP: Connect() timed out waiting for warp=on")
	return provider.Status{Connected: false, Provider: name, Location: "auto"}
}

// Disconnect tears the tunnel down AND deletes the registration so
// the next Connect() gets a fresh anonymous identity. Cloudflare
// usually assigns a different edge IP to a fresh registration,
// which is how WARP-as-a-provider gives the rotator IP rotation
// semantics matching what OpenVPN providers provide via location
// switching.
func (w WARP) Disconnect(ctx context.Context) error {
	_, _ = runCli(ctx, "disconnect")
	// Best-effort: deleting registration on disconnect realises
	// rotation; if it fails (e.g. already gone), Connect will
	// re-register from scratch on the way back up.
	_, _ = runCli(ctx, "registration", "delete")
	return nil
}

// Connected probes Cloudflare's trace endpoint. That's the most
// authoritative signal — `warp-cli status` says "Connected" before
// traffic is actually flowing through the tunnel.
func (w WARP) Connected(ctx context.Context) bool {
	out, err := shared.RunCmd(ctx, "curl", "-s", "--max-time", "3",
		"https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return false
	}
	for _, ln := range strings.Split(out, "\n") {
		if strings.TrimSpace(ln) == "warp=on" {
			return true
		}
	}
	return false
}

// Locations returns the single sentinel "auto". WARP picks the
// exit colo automatically; the location picker upstream just needs
// a non-empty slice to feed Connect().
func (w WARP) Locations(ctx context.Context) []string {
	return []string{"auto"}
}

// ActiveLocation returns the colo identifier reported by
// cloudflare's trace endpoint (e.g. "FRA", "AMS") — more
// informative than the "auto" sentinel and easier to correlate
// against geographic crawl behaviour.
func (w WARP) ActiveLocation(ctx context.Context) string {
	if colo := w.colo(ctx); colo != "" {
		return colo
	}
	return "auto"
}

// colo extracts the `colo=XXX` field from cloudflare's trace.
func (w WARP) colo(ctx context.Context) string {
	out, err := shared.RunCmd(ctx, "curl", "-s", "--max-time", "3",
		"https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "colo=") {
			return strings.TrimPrefix(ln, "colo=")
		}
	}
	return ""
}

// Status reports the live tunnel state — Connected, exit IP, and
// the colo as Region. Exit IP comes from a separate checkip query
// because cloudflare's own trace endpoint doesn't include the
// publicly-visible IP (only the internal one).
func (w WARP) Status(ctx context.Context) provider.Status {
	if !w.Connected(ctx) {
		return provider.Status{Connected: false, Provider: name}
	}
	ip, _ := shared.RunCmd(ctx, "curl", "-s", "--max-time", "3",
		"https://checkip.amazonaws.com")
	return provider.Status{
		Connected: true,
		IP:        strings.TrimSpace(ip),
		Location:  "auto",
		Region:    w.colo(ctx),
		Provider:  name,
	}
}

// Version returns warp-cli's reported version string.
func (w WARP) Version(ctx context.Context) (string, error) {
	out, err := runCli(ctx, "--version")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0]), nil
}
