package ovpn

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a log sink safe for the runner's background goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return buf
}

func TestTailKeepsTheLastLinesRedacted(t *testing.T) {
	const user, pass = "synthetic-user", "synthetic-pass"
	tl := newTail(user, pass)
	write := func(s string) { _, _ = tl.Write([]byte(s)) }
	write("Enter Auth Username: " + user + "\n")
	write("MANAGEMENT: CMD 'hold release'\n")
	write("PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,auth-token SESS_abc123,ifconfig 10.8.0.6 255.255.255.0'\n")
	write("echo " + pass + " back\n")
	write("TLS Error: TLS key nego")
	write("tiation failed to occur within 60 seconds\n")
	got := strings.Join(tl.snapshot(), "\n")
	for _, leaked := range []string{user, pass, "SESS_abc123", "hold release"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("tail kept %q:\n%s", leaked, got)
		}
	}
	for _, want := range []string{"auth-token [redacted]", "ifconfig 10.8.0.6", "echo [redacted] back", "TLS Error: TLS key negotiation failed to occur within 60 seconds"} {
		if !strings.Contains(got, want) {
			t.Fatalf("tail is missing %q:\n%s", want, got)
		}
	}
	for i := range 2 * tailLines {
		write(fmt.Sprintf("line %d\n", i))
	}
	lines := tl.snapshot()
	if len(lines) != tailLines || lines[0] != fmt.Sprintf("line %d", tailLines) || lines[tailLines-1] != fmt.Sprintf("line %d", 2*tailLines-1) {
		t.Fatalf("tail did not keep the last %d lines: %q", tailLines, lines)
	}
}

func TestAFailedAttemptLogsTheOpenVPNOutput(t *testing.T) {
	logs := captureLog(t)
	bin := t.TempDir()
	script := "#!/bin/sh\necho 'TCP: connect to [AF_INET]192.0.2.10:443 failed: Connection refused'\necho 'leaking synthetic-pass'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "openvpn"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, err := Start(context.Background(), Options{Name: "Test", RunDir: t.TempDir(), User: "u", Pass: "synthetic-pass"}, func(socket string) ([]byte, error) {
		return []byte("client\n" + Directives(socket)), nil
	})
	if err == nil {
		t.Fatal("an openvpn that exits must fail the start")
	}
	got := logs.String()
	for _, want := range []string{"ovpn: Test: connect attempt failed: Test OpenVPN exited during startup", "| TCP: connect to [AF_INET]192.0.2.10:443 failed: Connection refused", "| leaking [redacted]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "synthetic-pass") {
		t.Fatalf("log leaked the password:\n%s", got)
	}
}

func TestOnlyAnUnexpectedExitLogsADrop(t *testing.T) {
	logs := captureLog(t)
	launch := func() *Tunnel {
		socket, _ := managementFixture(t, "u1", "p1", true)
		tunnel, err := Launch(context.Background(), Options{Name: "Test", User: "u1", Pass: "p1"}, "client.ovpn", socket)
		if err != nil {
			t.Fatal(err)
		}
		return tunnel
	}
	stopped := launch()
	if err := stopped.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if strings.Contains(logs.String(), "tunnel dropped") {
		t.Fatalf("a requested stop was logged as a drop:\n%s", logs.String())
	}
	dropped := launch()
	t.Cleanup(func() { _ = dropped.Stop(context.Background()) })
	_ = dropped.cmd.Process.Kill()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "ovpn: Test: tunnel dropped: openvpn exited") {
		if time.Now().After(deadline) {
			t.Fatalf("an unexpected exit was not logged:\n%s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
