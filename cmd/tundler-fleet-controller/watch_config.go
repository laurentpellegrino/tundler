package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// configWatcher watches the directory holding vpn-providers.yaml so it
// can notice k8s ConfigMap atomic-symlink-swap updates and trigger a
// CDS rebuild (= xDS snapshot push to the hub envoy).
//
// k8s mounts a ConfigMap as a symlinked layout:
//
//	/etc/vpn-providers/
//	├── ..data -> ..2026_05_19_12_34_56.123456789/
//	├── ..2026_05_19_12_34_56.123456789/
//	│   └── vpn-providers.yaml
//	└── vpn-providers.yaml -> ..data/vpn-providers.yaml
//
// When the ConfigMap changes, k8s writes a new timestamp dir and
// atomically renames `..data` to point at it. The Rename fires
// fsnotify events on the parent directory (the symlinked file path
// itself doesn't emit Write events the way a normal file would). So we
// watch the *parent directory* and re-read on any relevant event.
//
// Debounced: a single ConfigMap update emits a Create + a Remove
// (sometimes Rename) close together. We collapse them into one rebuild
// via a 250 ms tail-quiet timer.
type configWatcher struct {
	path     string
	onReload func(newConfigured map[string]int)
}

// watchConfig blocks until ctx is done. Returns an error if the
// fsnotify watcher can't be created or attached to the directory.
func (c *configWatcher) watchConfig(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("new fsnotify watcher: %w", err)
	}
	defer w.Close()

	dir := filepath.Dir(c.path)
	if err := w.Add(dir); err != nil {
		return fmt.Errorf("watch %s: %w", dir, err)
	}
	log.Printf("config watch: %s", dir)

	const debounce = 250 * time.Millisecond
	var timer *time.Timer
	fire := func() {
		newConfigured, err := loadConfigured(c.path)
		if err != nil {
			log.Printf("config reload failed (keeping previous state): %v", err)
			return
		}
		c.onReload(newConfigured)
	}
	schedule := func() {
		if timer == nil {
			timer = time.AfterFunc(debounce, fire)
			return
		}
		timer.Reset(debounce)
	}

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			// React to any event in the watched dir that could mean
			// "the ConfigMap was updated". K8s emits Create+Rename on
			// the parent dir; a hand-edit on the symlinked path emits
			// Write. We don't try to be surgical — schedule() is
			// debounced, so repeated events collapse anyway.
			if ev.Op&(fsnotify.Create|fsnotify.Rename|fsnotify.Write|fsnotify.Remove) != 0 {
				schedule()
			}
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			log.Printf("config watch error: %v", err)
		}
	}
}
