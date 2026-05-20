package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestConfigWatcher_FiresOnWrite covers the simplest case: someone
// rewrites vpn-providers.yaml in place (the way local dev or a
// hand-edit on the host would). The watcher debounces and fires once
// with the new state.
func TestConfigWatcher_FiresOnWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vpn-providers.yaml")
	initial := `
providers:
  expressvpn:
    max_tunnels: 7
`
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	got := make(chan map[string]int, 4)
	w := &configWatcher{path: path, onReload: func(m map[string]int) { got <- m }}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- w.watchConfig(ctx) }()

	// Tiny pause to make sure the watcher is set up before we mutate.
	time.Sleep(100 * time.Millisecond)

	updated := `
providers:
  expressvpn:
    max_tunnels: 7
  nordvpn:
    max_tunnels: 9
`
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatalf("update file: %v", err)
	}

	select {
	case m := <-got:
		if m["nordvpn"] != 9 {
			t.Errorf("got=%v, want nordvpn=9", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("config reload did not fire within 2s")
	}
}

// TestConfigWatcher_BadConfigKeepsPreviousState covers the safety
// behavior: if the new file is malformed, onReload is NOT called (the
// fleet-controller keeps serving the previous snapshot). A future valid
// update still works.
func TestConfigWatcher_BadConfigKeepsPreviousState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vpn-providers.yaml")
	if err := os.WriteFile(path, []byte("providers: { expressvpn: { max_tunnels: 7 } }"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	var reloadCount atomic.Int32
	w := &configWatcher{path: path, onReload: func(_ map[string]int) { reloadCount.Add(1) }}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.watchConfig(ctx)
	time.Sleep(100 * time.Millisecond)

	// Write garbage — should NOT fire onReload.
	if err := os.WriteFile(path, []byte("nope: : : not yaml"), 0o644); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	time.Sleep(600 * time.Millisecond)

	// Recover with a valid file — onReload SHOULD fire.
	if err := os.WriteFile(path, []byte("providers: { expressvpn: { max_tunnels: 9 } }"), 0o644); err != nil {
		t.Fatalf("write good: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if reloadCount.Load() == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("onReload fired %d times, want 1 (only the valid file)", reloadCount.Load())
}

// TestConfigWatcher_DebouncesBurstEvents covers k8s' multi-event
// ConfigMap update (Create + Rename + Remove fire back-to-back). The
// watcher's 250 ms debounce window collapses these into one reload.
func TestConfigWatcher_DebouncesBurstEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vpn-providers.yaml")
	if err := os.WriteFile(path, []byte("providers: { expressvpn: { max_tunnels: 1 } }"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var reloadCount atomic.Int32
	w := &configWatcher{path: path, onReload: func(_ map[string]int) { reloadCount.Add(1) }}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.watchConfig(ctx)
	time.Sleep(100 * time.Millisecond)

	// Fire several writes inside the debounce window.
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(path, []byte("providers: { expressvpn: { max_tunnels: 2 } }"), 0o644); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(30 * time.Millisecond)
	}
	// Wait past the debounce tail.
	time.Sleep(500 * time.Millisecond)
	if got := reloadCount.Load(); got != 1 {
		t.Errorf("onReload fired %d times for 5 bursty writes, want 1 (debounced)", got)
	}
}

// TestConfigWatcher_ConfigMapSymlinkSwap mimics how k8s actually updates
// a mounted ConfigMap: write the new contents into a fresh "timestamp"
// directory, then atomically rename the `..data` symlink in the mount
// directory. fsnotify on the parent dir should still pick this up and
// the watcher should re-read the symlinked path.
func TestConfigWatcher_ConfigMapSymlinkSwap(t *testing.T) {
	root := t.TempDir()
	// Initial layout:
	//   root/
	//     ..ts1/vpn-providers.yaml
	//     ..data -> ..ts1
	//     vpn-providers.yaml -> ..data/vpn-providers.yaml
	ts1 := filepath.Join(root, "..ts1")
	if err := os.MkdirAll(ts1, 0o755); err != nil {
		t.Fatalf("mkdir ts1: %v", err)
	}
	ts1File := filepath.Join(ts1, "vpn-providers.yaml")
	if err := os.WriteFile(ts1File, []byte("providers: { expressvpn: { max_tunnels: 7 } }"), 0o644); err != nil {
		t.Fatalf("write ts1 file: %v", err)
	}
	dataLink := filepath.Join(root, "..data")
	if err := os.Symlink("..ts1", dataLink); err != nil {
		t.Fatalf("symlink ..data: %v", err)
	}
	target := filepath.Join(root, "vpn-providers.yaml")
	if err := os.Symlink("..data/vpn-providers.yaml", target); err != nil {
		t.Fatalf("symlink vpn-providers.yaml: %v", err)
	}

	got := make(chan map[string]int, 4)
	w := &configWatcher{path: target, onReload: func(m map[string]int) { got <- m }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.watchConfig(ctx)
	time.Sleep(100 * time.Millisecond)

	// Simulate k8s update: new ..ts2 dir + atomic rename of ..data.
	ts2 := filepath.Join(root, "..ts2")
	if err := os.MkdirAll(ts2, 0o755); err != nil {
		t.Fatalf("mkdir ts2: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ts2, "vpn-providers.yaml"),
		[]byte("providers: { expressvpn: { max_tunnels: 7 }, nordvpn: { max_tunnels: 9 } }"),
		0o644); err != nil {
		t.Fatalf("write ts2 file: %v", err)
	}
	// Atomic-rename trick: create temp symlink, then rename it over ..data.
	tmpLink := filepath.Join(root, "..data.tmp")
	if err := os.Symlink("..ts2", tmpLink); err != nil {
		t.Fatalf("tmp symlink: %v", err)
	}
	if err := os.Rename(tmpLink, dataLink); err != nil {
		t.Fatalf("atomic rename: %v", err)
	}

	select {
	case m := <-got:
		if m["nordvpn"] != 9 {
			t.Errorf("after ConfigMap-style swap: got=%v, want nordvpn=9", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ConfigMap-style symlink swap did not trigger reload within 2s")
	}
}
