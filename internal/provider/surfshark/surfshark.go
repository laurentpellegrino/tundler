package surfshark

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/laurentpellegrino/tundler/internal/provider"
	"github.com/laurentpellegrino/tundler/internal/shared"
)

type Surfshark struct{}

const bin = "surfshark-vpn"
const name = "surfshark"

func init() { provider.Registry[name] = Surfshark{} }

// runCmd runs surfshark-vpn with empty stdin (required by CLI to avoid prompts)
func runCmd(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader("")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func quiet(ctx context.Context, args ...string) { _, _ = runCmd(ctx, args...) }

func (s Surfshark) ActiveLocation(ctx context.Context) string {
	out, _ := runCmd(ctx, "status")
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		// Parse "You are connected to: <location>" or similar
		if strings.Contains(strings.ToLower(ln), "connected to") {
			parts := strings.SplitN(ln, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(ln, "Server:") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "Server:"))
		}
		if strings.HasPrefix(ln, "Location:") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "Location:"))
		}
	}
	return ""
}

func (s Surfshark) Connect(ctx context.Context, location string) provider.Status {
	if location != "" {
		// The CLI uses numeric selection, but we can try passing location directly
		// or use 'attack' for quick connect to optimal
		quiet(ctx, location)
	} else {
		// Use 'attack' for quick connect to optimal location
		quiet(ctx, "attack")
	}
	return s.Status(ctx)
}

func (s Surfshark) Connected(ctx context.Context) bool {
	out, _ := runCmd(ctx, "status")
	lower := strings.ToLower(out)
	return strings.Contains(lower, "connected") &&
		!strings.Contains(lower, "not connected") &&
		!strings.Contains(lower, "disconnected")
}

func (s Surfshark) Disconnect(ctx context.Context) error {
	_, err := runCmd(ctx, "down")
	return err
}

func (s Surfshark) Locations(ctx context.Context) []string {
	// The legacy CLI doesn't have a locations list command
	// Return common country codes that Surfshark supports
	return []string{}
}

func (s Surfshark) LoggedIn(ctx context.Context) bool {
	// surfshark-vpn stores credentials in ~/.surfshark/credentials/
	// Check if credential files exist
	entries, err := os.ReadDir(os.ExpandEnv("$HOME/.surfshark/credentials"))
	if err != nil {
		return false
	}
	return len(entries) > 0
}

func (s Surfshark) Login(ctx context.Context) error {
	email := os.Getenv("SURFSHARK_EMAIL")
	pass := os.Getenv("SURFSHARK_PASSWORD")

	if email == "" || pass == "" {
		return fmt.Errorf("SURFSHARK_EMAIL and SURFSHARK_PASSWORD environment variables not set")
	}
	if s.LoggedIn(ctx) {
		return nil
	}

	// Use expect to handle interactive login prompts
	expectScript := fmt.Sprintf(`
set timeout 30
spawn %s
expect "email:"
send "%s\r"
expect "assword:"
send "%s\r"
expect eof
`, bin, email, pass)

	cmd := exec.CommandContext(ctx, "expect", "-c", expectScript)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("surfshark login failed: %w: %s", err, out.String())
	}
	return nil
}

func (s Surfshark) Logout(ctx context.Context) error {
	_, err := runCmd(ctx, "forget")
	return err
}

func (s Surfshark) Status(ctx context.Context) provider.Status {
	if !s.Connected(ctx) {
		return provider.Status{Connected: false}
	}
	out, _ := runCmd(ctx, "status")
	return provider.Status{
		Connected: true,
		IP:        shared.FirstIPv4(out),
		Location:  s.ActiveLocation(ctx),
		Provider:  name,
	}
}

func (s Surfshark) Version(ctx context.Context) (string, error) {
	out, err := runCmd(ctx, "version")
	if err != nil {
		// Try --version flag
		out, err = runCmd(ctx, "--version")
		if err != nil {
			return "", err
		}
	}
	if v := shared.ExtractVersion(out); v != "" {
		return v, nil
	}
	return strings.TrimSpace(out), nil
}
