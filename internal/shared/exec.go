package shared

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
)

func withNetNS(name string, args []string) (string, []string) {
	ns := os.Getenv("TUNDLER_NETNS")
	if ns == "" {
		return name, args
	}
	all := append([]string{"netns", "exec", ns, name}, args...)
	return "ip", all
}

func RunAsync(ctx context.Context, name string, args ...string) error {
	name, args = withNetNS(name, args)
	cmd := exec.CommandContext(ctx, name, args...)
	Debugf("[async] %s %v", name, args)
	return cmd.Start() // fire-and-forget
}

func RunCmd(ctx context.Context, name string, args ...string) (string, error) {
	name, args = withNetNS(name, args)
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	Debugf("[%s] %s", name, out)
	if err != nil {
		Debugf("[%s] error: %v", name, err)
	}
	return out, err
}

// RunCmdDirect runs a command without network namespace wrapping.
// Use this for CLIs that need host network access (e.g., surfshark-vpn).
func RunCmdDirect(ctx context.Context, name string, args ...string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	Debugf("[direct] %s %s", name, out)
	if err != nil {
		Debugf("[direct] %s error: %v", name, err)
	}
	return out, err
}

// FirstIPv4 extracts the first IPv4 address found in the given string.
func FirstIPv4(s string) string {
	for _, tok := range strings.Fields(s) {
		if strings.Count(tok, ".") == 3 {
			return tok
		}
	}
	return ""
}
