package nordvpn

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

type NordVPN struct{}

const bin = "nordvpn"
const name = bin

func init() { provider.Registry[name] = NordVPN{} }

func quiet(ctx context.Context, args ...string) { _, _ = shared.RunCmd(ctx, bin, args...) }

func (n NordVPN) Connect(ctx context.Context, location string) provider.Status {
	args := []string{"connect"}
	if location != "" {
		args = append(args, location)
	}
	quiet(ctx, args...)
	return n.Status(ctx)
}

func (n NordVPN) Connected(ctx context.Context) bool {
	out, _ := shared.RunCmd(ctx, bin, "status")
	return strings.Contains(out, "Status: Connected")
}

func (n NordVPN) Disconnect(ctx context.Context) error {
	_, err := shared.RunCmd(ctx, bin, "disconnect")
	return err
}

func (n NordVPN) Locations(ctx context.Context) []string {
	out, _ := shared.RunCmd(ctx, bin, "countries")
	return strings.Fields(out)
}

func (n NordVPN) LoggedIn(ctx context.Context) bool {
	out, _ := shared.RunCmd(ctx, bin, "login")
	return strings.Contains(out, "You are already logged in.")
}

func (n NordVPN) Login(ctx context.Context) error {
	token := os.Getenv("NORDVPN_TOKEN")
	if token == "" {
		return fmt.Errorf("NORDVPN_TOKEN environment variable not set")
	}
	if n.LoggedIn(ctx) {
		return nil
	}
	if _, err := shared.RunCmd(ctx, bin, "login", "--token", token); err != nil {
		return fmt.Errorf("nordvpn login failed: %w", err)
	}
	return nil
}

func (n NordVPN) Logout(ctx context.Context) error {
	_, err := shared.RunCmd(ctx, bin, "logout", "--persist-token")
	return err
}

func (n NordVPN) Status(ctx context.Context) provider.Status {
	if !n.Connected(ctx) {
		return provider.Status{Connected: false}
	}
	out, _ := shared.RunCmd(ctx, bin, "status") // needed for the public IP
	return provider.Status{
		Connected: true,
		IP:        shared.FirstIPv4(out),
		Provider:  name,
	}
}

func (n NordVPN) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, bin, "--version")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(out), nil
}
