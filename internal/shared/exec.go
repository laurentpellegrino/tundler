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

// withNetNS wraps the command under `ip netns exec <TUNDLER_NETNS>`
// IF the env var is set. Returns the command unchanged otherwise.
// Only consumed by the RunCmdNetNS family — the default RunCmd path
// deliberately never calls this so a misconfigured env var can't
// silently drop a provider's tunnel into the wrong namespace.
func withNetNS(name string, args []string) (string, []string) {
	ns := os.Getenv("TUNDLER_NETNS")
	if ns == "" {
		return name, args
	}
	all := append([]string{"netns", "exec", ns, name}, args...)
	return "ip", all
}

// ---------------------------------------------------------------------------
// Default family: MAIN namespace. No wrapping. This is what almost every
// provider call should use — daemons (expressvpnd/piad/nordvpnd) live in
// main ns, the openvpn/wg-quick processes that build tun0/wg0 live in
// main ns (because the in-process CONNECT proxy lives there and needs the
// VPN to be the main-ns default route), and CLI calls into those daemons
// reach them over filesystem-bound IPC regardless of netns. A leak via the
// node IP is the canonical failure mode of putting a tunnel in the wrong
// namespace, so we make the safe choice the default and require explicit
// opt-in for the wrapping variant.
// ---------------------------------------------------------------------------

// RunCmd runs a child process in the caller's (main) network namespace
// and returns its trimmed stdout+stderr. Logs a single Debugf line with
// the captured output and any error. Use this for almost everything —
// the only legitimate use of the *NetNS family is a command that MUST
// observe vpnns state (rare in the per-pod VPN-hub architecture).
func RunCmd(ctx context.Context, name string, args ...string) (string, error) {
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

// RunCmdSilent is RunCmd minus the per-call Debugf logging. Pair with
// hot-path polling — e.g. the `ip route show dev tun0` loops the
// OpenVPN-direct providers run while waiting for the tunnel to come
// up. Each poll otherwise logs "Cannot find device tun0" + "exit
// status 1" at ~2 Hz, flooding journald and burying the real
// connect-failure messages.
func RunCmdSilent(ctx context.Context, name string, args ...string) (string, error) {
	var buf bytes.Buffer
	sink := newBoundedSink(&buf)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = sink
	cmd.Stderr = sink
	err := cmd.Run()
	return strings.TrimSpace(buf.String()), err
}

// RunAsync starts a process and returns immediately — fire-and-forget.
// Used for daemons we don't want to .Wait() on (the parent typically
// supervises them externally — e.g., systemd, or a periodic CLI poll).
func RunAsync(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	Debugf("[async] %s %v", name, args)
	return cmd.Start()
}

// ---------------------------------------------------------------------------
// Opt-in family: wraps under `ip netns exec $TUNDLER_NETNS`. The wrap is
// applied ONLY when the env var is set, so unit tests in vanilla CI
// containers (no netns set up) still exercise the same code paths.
//
// Use cases that justify *NetNS:
//   - a probe that legitimately needs to observe vpnns-side state (e.g.
//     verifying the netns scaffolding is intact)
//   - a CLI that, by design, opens a network socket from inside vpnns
//     for traffic isolation (not currently used by any provider — the
//     per-pod architecture puts daemons + tunnels in main ns)
// Everything else should use RunCmd.
// ---------------------------------------------------------------------------

// RunCmdNetNS is RunCmd, but wraps the command under
// `ip netns exec $TUNDLER_NETNS` when the env var is set.
func RunCmdNetNS(ctx context.Context, name string, args ...string) (string, error) {
	name, args = withNetNS(name, args)
	var buf bytes.Buffer
	sink := newBoundedSink(&buf)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = sink
	cmd.Stderr = sink
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	Debugf("[netns %s] %s", name, out)
	if err != nil {
		Debugf("[netns %s] error: %v", name, err)
	}
	return out, err
}

// RunCmdSilentNetNS is RunCmdSilent with netns wrapping. See RunCmdNetNS.
func RunCmdSilentNetNS(ctx context.Context, name string, args ...string) (string, error) {
	name, args = withNetNS(name, args)
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
