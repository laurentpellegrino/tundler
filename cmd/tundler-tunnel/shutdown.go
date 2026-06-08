package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/laurentpellegrino/tundler/internal/provider"
)

// shutdownDisconnectTimeout bounds the best-effort teardown. The binding
// constraint on the graceful path is systemd's DefaultTimeoutStopSec=10s
// (docker/Dockerfile.tunnel) — on pod delete the runtime sends STOPSIGNAL
// SIGRTMIN+3 to PID-1 systemd, which halts and SIGTERMs this unit, then
// SIGKILLs it after 10s. So keep the Disconnect well under 10s; if it
// hasn't returned, we let systemd/kernel tear the netns down and rely on
// the provider's server-side idle timeout to reclaim the device slot.
const shutdownDisconnectTimeout = 8 * time.Second

var (
	shutdownMu       sync.Mutex
	shutdownProv     provider.VPNProvider
	shutdownProvName string
	shutdownDone     bool
)

// registerShutdownDisconnect records the active provider so that EVERY
// process-exit path (SIGTERM hold, failAndExit, the wedge guard, and the
// self-recycle) can release the VPN session client-side before the
// process/container goes away.
//
// This matters because VPN providers do NOT retain server-side device
// records we can clean up later — confirmed with ExpressVPN support: an
// abandoned tunnel stays "connected" on the account until WE disconnect
// it from the client. Leaving sessions dangling (then opening a fresh one
// on restart) makes one account look like many concurrent devices, which
// is exactly what trips their shared-account / too-many-devices throttle.
// Call once, right after the provider is resolved in main().
func registerShutdownDisconnect(prov provider.VPNProvider, providerName string) {
	shutdownMu.Lock()
	defer shutdownMu.Unlock()
	shutdownProv = prov
	shutdownProvName = providerName
}

// gracefulDisconnect tears down the VPN tunnel so the provider backend
// frees the device slot. It is:
//   - best-effort: Disconnect errors are logged, never fatal (we're already
//     on the way out; the netns teardown removes the interface regardless);
//   - idempotent: runs at most once even if several exit paths race;
//   - context-safe: it builds a FRESH (non-cancelled) context. The caller's
//     ctx on the SIGTERM path is the signal context — already cancelled by
//     the time we get here — and passing it to Disconnect would abort the
//     daemon CLI call instantly, defeating the whole point.
func gracefulDisconnect() {
	shutdownMu.Lock()
	prov := shutdownProv
	name := shutdownProvName
	if prov == nil || shutdownDone {
		shutdownMu.Unlock()
		return
	}
	shutdownDone = true
	shutdownMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownDisconnectTimeout)
	defer cancel()
	log.Printf("tundler-tunnel: provider=%s disconnecting tunnel before exit (release device slot)", name)
	if err := prov.Disconnect(ctx); err != nil {
		log.Printf("tundler-tunnel: provider=%s shutdown Disconnect failed (continuing exit): %v", name, err)
		return
	}
	log.Printf("tundler-tunnel: provider=%s tunnel disconnected cleanly before exit", name)
}
