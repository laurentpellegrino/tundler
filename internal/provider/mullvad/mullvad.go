package mullvad

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

const bin = "mullvad"
const name = bin

type Mullvad struct{}

func init() { provider.Registry[name] = Mullvad{} }

func quiet(ctx context.Context, args ...string) { _, _ = shared.RunCmd(ctx, bin, args...) }

func (m Mullvad) ActiveLocation(ctx context.Context) string {
	out, _ := shared.RunCmd(ctx, bin, "status")
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "Relay:") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "Relay:"))
		}
	}
	return ""
}

func (m Mullvad) Connect(ctx context.Context, location string) provider.Status {
	if location != "" {
		quiet(ctx, "relay", "set", "location", location)
	}

	quiet(ctx, "connect", "--wait")
	return m.Status(ctx)
}

func (m Mullvad) Connected(ctx context.Context) bool {
	out, _ := shared.RunCmd(ctx, bin, "status")
	return strings.Contains(out, "Connected")
}

func (m Mullvad) Disconnect(ctx context.Context) error {
	_, err := shared.RunCmd(ctx, bin, "disconnect", "--wait")
	return err
}

func (m Mullvad) Locations(ctx context.Context) []string {
	out, _ := shared.RunCmd(ctx, bin, "relay", "list")
	var cc []string
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "\t") || strings.HasPrefix(ln, " ") {
			continue // skip server entries
		}
		line := strings.TrimSpace(ln)
		if line == "" || !strings.Contains(line, "(") || !strings.Contains(line, ")") {
			continue
		}
		start := strings.Index(line, "(")
		end := strings.Index(line[start+1:], ")")
		if end < 0 {
			continue
		}
		cc = append(cc, strings.TrimSpace(line[start+1:start+1+end]))
	}
	return cc
}

func (m Mullvad) LoggedIn(ctx context.Context) bool {
	out, _ := shared.RunCmd(ctx, bin, "account", "get")
	return !strings.Contains(out, "Not logged in")
}

func (m Mullvad) Login(ctx context.Context) error {
	acct := os.Getenv("MULLVAD_ACCOUNT_NUMBER")
	if acct == "" {
		return fmt.Errorf("MULLVAD_ACCOUNT_NUMBER environment variable not set")
	}
	if m.LoggedIn(ctx) {
		return nil
	}
	if _, err := shared.RunCmd(ctx, bin, "account", "login", acct); err != nil {
		return fmt.Errorf("mullvad account login failed: %w", err)
	}
	return nil
}

func (m Mullvad) Logout(ctx context.Context) error {
	_, err := shared.RunCmd(ctx, bin, "account", "logout")
	return err
}

func (m Mullvad) Status(ctx context.Context) provider.Status {
	out, _ := shared.RunCmd(ctx, bin, "status")
	if !strings.HasPrefix(out, "Connected") {
		return provider.Status{Connected: false}
	}
	ip := ""
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "Visible location:") {
			ip = shared.FirstIPv4(ln)
			break
		}
	}
	return provider.Status{
		Connected: true,
		IP:        ip,
		Location:  m.ActiveLocation(ctx),
		Provider:  name,
	}
}

func (m Mullvad) Version(ctx context.Context) (string, error) {
	out, err := shared.RunCmd(ctx, bin, "--version")
	if err != nil {
		return "", err
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(out), nil
}
