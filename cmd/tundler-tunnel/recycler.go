package main

import (
	"context"
	"log"
	"math/rand/v2"
	"os"
	"time"

	"github.com/laurentpellegrino/tundler/internal/shared"
)

// recycleRotationLimit, when > 0, makes runRotator recycle the container
// INSTEAD of performing the next SCHEDULED relocation once the pod has done
// that many (see runRotator). A recycle already yields a fresh exit IP, so
// it cleanly replaces a relocation while also refreshing the image + env.
// Only scheduled relocations count — crawler /rotate (throttle recovery)
// must not trigger recycles. Set in main() from RECYCLE_AFTER_ROTATIONS;
// 0 in tests and when periodic rotation is disabled.
var recycleRotationLimit int

// recycleContainer gracefully drains and then terminates the CONTAINER so
// kubelet recreates it on the latest image (imagePullPolicy: Always) with
// freshly-rendered env. This is how new builds + config roll out
// automatically — no hand-restarts, no waiting on a slow ordinal-gated
// RollingUpdate.
//
// Why exit PID 1 (systemd) and not os.Exit: the binary runs under systemd
// with Restart=always, so os.Exit only respawns the PROCESS inside the SAME
// container — same image, same boot-time EnvironmentFile. Exiting systemd
// terminates the container, which kubelet restarts with a fresh image pull.
func recycleContainer(ctx context.Context, state *StateTracker, drain drainController, reason string) {
	log.Printf("tundler-tunnel: recycling (%s) — draining then exiting container to refresh image/config", reason)
	// Flip /readyz→503 so the crawler stops routing here and the headless
	// Service drops the pod from its endpoints, then drain in-flight CONNECTs.
	state.Set(StateDraining)
	if drain != nil {
		_ = drain.TriggerGracefulDrain(ctx)
		_ = drain.WaitForActiveConnectionsToDrain(ctx, 30*time.Second)
	}
	// `systemctl exit 0` asks PID-1 systemd to terminate the whole container
	// (allowed for the system manager only when running in a container —
	// exactly our case), so kubelet repulls the image. os.Exit alone would
	// only respawn the process inside the same container via Restart=always.
	if _, err := shared.RunCmd(ctx, "systemctl", "exit", "0"); err != nil {
		log.Printf("tundler-tunnel: `systemctl exit` failed (%v); falling back to process exit", err)
	}
	// Guaranteed backstop: whether systemctl reported success or silently
	// no-op'd, exit the process so we never wedge in Draining (unready
	// forever). If the container is already tearing down this is moot; if it
	// isn't, this at least frees the slot and systemd respawns us clean.
	time.Sleep(5 * time.Second)
	os.Exit(0)
}

// runRecycler is the TIME-based recycle backstop: after a jittered max
// lifetime it recycles the container (the rotation-count trigger lives in
// the rotator so it can replace a rotation rather than pile on after one).
func runRecycler(ctx context.Context, state *StateTracker, drain drainController, lifetime time.Duration) {
	if lifetime <= 0 {
		return
	}
	// Jitter by up to +33% so a fleet configured with the same value doesn't
	// recycle in lockstep (on top of per-pod boot/rotation desync).
	lifetime += time.Duration(rand.Int64N(int64(lifetime)/3 + 1))
	deadline := time.Now().Add(lifetime)
	log.Printf("tundler-tunnel: recycler armed — max lifetime ~%s", lifetime.Round(time.Minute))

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Now().Before(deadline) {
				continue
			}
			// Only recycle from a calm Ready state — catch the next Ready
			// window rather than draining mid-rotation or mid-failure.
			if state.Get() != StateReady {
				continue
			}
			recycleContainer(ctx, state, drain, "max lifetime reached")
			return
		}
	}
}
