package shared

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
)

// runCmdOutputCap bounds the in-memory buffer that captures a child
// process's stdout+stderr. Without this, a long-running CLI that emits
// progress output (e.g. `nordvpn login --token …` emits ~5 MB/s of
// spinner frames) will balloon the parent's heap and OOMKill the pod.
//
// 64 KiB is well above what any provider plugin parses (countries
// list, status text, login confirmation are all <2 KB). Everything
// beyond the cap is silently discarded — the captured prefix is
// enough for any error message we'd want to log.
const runCmdOutputCap = 64 * 1024

// boundedWriter is an io.Writer that captures up to cap bytes and
// silently drops the rest. Used as the stdout/stderr sink for
// exec'd commands so long-running CLIs can't OOM the parent.
type boundedWriter struct {
	buf *bytes.Buffer
	cap int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	remaining := w.cap - w.buf.Len()
	if remaining <= 0 {
		return len(p), nil // pretend we wrote it; drop on the floor
	}
	if len(p) > remaining {
		w.buf.Write(p[:remaining])
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}

// newBoundedSink returns a writer that captures into buf up to
// runCmdOutputCap bytes total. Use the SAME sink for both stdout and
// stderr so the cap is shared (interleaved output stays consistent).
func newBoundedSink(buf *bytes.Buffer) io.Writer {
	return &boundedWriter{buf: buf, cap: runCmdOutputCap}
}

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
	sink := newBoundedSink(&buf)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = sink
	cmd.Stderr = sink
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	Debugf("[%s] %s", name, out)
	if err != nil {
		Debugf("[%s] error: %v", name, err)
	}
	return out, err
}

// RunCmdSilent is RunCmd but without the per-call Debugf logging.
// Use this for inside-the-hot-path polling commands — e.g. the
// `ip route show dev tun0` loop the OpenVPN providers run while
// waiting for the tunnel to come up. Each poll otherwise logs
// "Cannot find device tun0" + "exit status 1" via Debugf at ~2 Hz,
// flooding journald and burying the real connect-failure messages.
// Still applies the bounded-output sink + netns wrapping so the
// runtime behavior matches RunCmd in every other respect.
func RunCmdSilent(ctx context.Context, name string, args ...string) (string, error) {
	name, args = withNetNS(name, args)
	var buf bytes.Buffer
	sink := newBoundedSink(&buf)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = sink
	cmd.Stderr = sink
	err := cmd.Run()
	return strings.TrimSpace(buf.String()), err
}

// RunCmdDirect runs a command without network namespace wrapping.
// Use this for CLIs that need host network access (e.g., surfshark-vpn).
func RunCmdDirect(ctx context.Context, name string, args ...string) (string, error) {
	var buf bytes.Buffer
	sink := newBoundedSink(&buf)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = sink
	cmd.Stderr = sink
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	Debugf("[direct] %s %s", name, out)
	if err != nil {
		Debugf("[direct] %s error: %v", name, err)
	}
	return out, err
}

// RunCmdSilentDirect is RunCmdDirect minus the per-call Debugf logging.
// Pair with the connect-poll loops in the OpenVPN-direct providers
// (ipvanish/protonvpn) — those poll `ip route show dev tun0` at 2 Hz
// while waiting for openvpn to push routes, and the verbose variant
// would flood journald with "Cannot find device tun0" + exit-status
// chatter that buries real connect-failure messages.
func RunCmdSilentDirect(ctx context.Context, name string, args ...string) (string, error) {
	var buf bytes.Buffer
	sink := newBoundedSink(&buf)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = sink
	cmd.Stderr = sink
	err := cmd.Run()
	return strings.TrimSpace(buf.String()), err
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
