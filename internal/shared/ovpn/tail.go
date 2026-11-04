package ovpn

import (
	"bytes"
	"log"
	"regexp"
	"strings"
	"sync"
)

// tailLines is how many lines of openvpn output a Tunnel keeps for the
// log when an attempt fails or a tunnel drops.
const tailLines = 20

// tailLineMax caps one kept line, so a runaway line cannot flood the log.
const tailLineMax = 300

// tokenRe matches a session token pushed by the server or echoed back,
// wherever it appears in a line (PUSH_REPLY options are comma-separated).
var tokenRe = regexp.MustCompile(`(?i)(auth-token(?:-user)?)[ \t]+[^,'"\s]+`)

// tail is the openvpn child's stdout and stderr: it keeps the last
// lines, redacted, and drops everything else. The account credentials
// never reach it in a usable form: lines that mention a username or
// password, or a management command, are dropped whole, the literal
// username and password are replaced wherever they appear, and pushed
// session tokens are masked.
type tail struct {
	mu      sync.Mutex
	secrets []string
	partial []byte
	lines   []string
}

func newTail(user, pass string) *tail {
	t := &tail{}
	for _, s := range []string{user, pass} {
		if len(s) >= 3 {
			t.secrets = append(t.secrets, s)
		}
	}
	return t
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.partial = append(t.partial, p...)
	for {
		i := bytes.IndexByte(t.partial, '\n')
		if i < 0 {
			break
		}
		t.add(string(t.partial[:i]))
		t.partial = t.partial[i+1:]
	}
	if len(t.partial) > 4*tailLineMax {
		t.add(string(t.partial))
		t.partial = t.partial[:0]
	}
	return len(p), nil
}

func (t *tail) add(line string) {
	line = strings.TrimRight(line, "\r")
	if line == "" {
		return
	}
	lower := strings.ToLower(line)
	if strings.Contains(lower, "password") || strings.Contains(lower, "username") || strings.Contains(lower, "management: cmd") {
		return
	}
	for _, s := range t.secrets {
		line = strings.ReplaceAll(line, s, "[redacted]")
	}
	line = tokenRe.ReplaceAllString(line, "$1 [redacted]")
	if len(line) > tailLineMax {
		line = line[:tailLineMax] + "…"
	}
	t.lines = append(t.lines, line)
	if len(t.lines) > tailLines {
		t.lines = t.lines[len(t.lines)-tailLines:]
	}
}

// snapshot returns the kept lines, oldest first.
func (t *tail) snapshot() []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.lines...)
}

// logTail writes why, then the kept openvpn lines, one log line each.
func logTail(name string, t *tail, why string) {
	lines := t.snapshot()
	log.Printf("ovpn: %s: %s; last %d lines of openvpn output follow", name, why, len(lines))
	for _, line := range lines {
		log.Printf("ovpn: %s: | %s", name, line)
	}
}
