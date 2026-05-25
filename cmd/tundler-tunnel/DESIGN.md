# tundler-tunnel — design summary

Single-container, single-provider VPN runtime that runs in each per-provider
tunnel pod of the VPN-hub architecture. After the Phase 4 migration the pod
contains only this Go binary — no sibling envoy, no xDS server, no separate
proxy process. One Go runtime owns VPN provider, CONNECT proxy, control API,
and lifecycle.

## Process layout inside the pod

```
systemd (PID 1, from image entrypoint)
└─ tundler-tunnel.service              Restart=always
   └─ tundler-tunnel (single Go binary)
      ├─ goroutine: HTTP control API  (:4242 /livez /readyz /status /rotate)
      ├─ goroutine: CONNECT proxy     (:8485 — replaces removed envoy sidecar)
      ├─ goroutine: watchdog          (tunnel-health poller, resilient)
      ├─ goroutine: rotator           (hourly random rotation + /rotate trigger)
      ├─ goroutine: wedge guard       (last-resort restart trigger)
      └─ provider-specific subprocesses (piactl monitor / expressvpnctl background)
```

Crawler traffic flow:

```
crawler  ──HTTP CONNECT──▶  hub envoy (in tundler-fleet-controller pods)
                                │  weighted-RR across providers, outlier detection
                                ▼
                          tundler-tunnel pod  :8485   (Go CONNECT proxy)
                                │  bidirectional io.Copy through the VPN
                                ▼
                          internet via tun0
```

## Pod state machine

```
                  Booting
                     │  boot-login jitter
                     ▼
                 LoggingIn
                     │  provider.Login()
                     ▼
                Connecting  ◀───┐
                     │           │  watchdog reconnect
                     ▼           │
                  Ready  ────────┘
                  ▲ │
       /rotate or │ │  Disconnect()
       hourly tick│ ▼
              Draining  (proxy stops accepting new CONNECTs)
                  │
                  ▼
              Rotating  (Connect to new location, retry up to ROTATION_RETRY_MAX)
                  │
            ┌─────┴─────┐
         success      failure
            │           │
            ▼           ▼
          Ready       Failed  ◀── watchdog retries with backoff
                        │
                        └── stuck > WEDGE_GUARD_THRESHOLD ⇒ os.Exit(1)
```

## Probe semantics (k8s)

| probe     | what it answers                                | implementation                                          |
|-----------|------------------------------------------------|---------------------------------------------------------|
| `/livez`  | "is this *process* responsive?"                | **always 200** — serving the response IS the signal     |
| `/readyz` | "should this pod be in the LB pool right now?" | 200 iff `state == Ready`                                 |
| startup   | "has initial connect finished?"                 | same as `/readyz`, with a generous `failureThreshold`    |

`/livez` **does not** inspect VPN state. A rotation, a brief Failed window,
or a wedged provider daemon are not reasons for kubelet to recreate the
container — that would wipe `/var/log/journal` and bump the
kubelet-visible restart count. The runtime decides when to restart itself
via the **wedge guard** (see below), and lets systemd respawn the binary
in place.

This is a deliberate departure from the earlier design where `/livez`
returned 503 once state had been not-Ready for > 5 min. That had a clock
bug (the timer ran from the *last entry* into Ready, not the *last exit*)
and conflated liveness with readiness: a normal 60-90 s rotation could
trip it.

## Failure-handling layers

Three independent layers handle different failure modes:

### 1. Watchdog (resilient, in-process)

Every `TUNNEL_WATCHDOG_INTERVAL_SECONDS` (default 30 s) the watchdog
checks `provider.Connected()` when state is `Ready`. If the tunnel
dropped, it reconnects via `connectTunnel`.

Key property: **the watchdog goroutine never exits on failure.** A failed
reconnect sets state to `Failed`, then sleeps with exponential backoff
(5 s → 10 s → 20 s → 40 s → 60 s cap) and tries again on the next tick.
The watchdog also recovers from `Failed` — not just `Ready`-with-tunnel-down —
so a previous attempt's surrender doesn't park the pod indefinitely.

Earlier behavior: a single transient piactl/expressvpnctl blip flipped the
pod to `Failed` and exited the goroutine forever. The only recovery path
was the hourly rotator, which left an hour-long hole that the `/livez`
clock would eat through and turn into a kubelet kill.

### 2. Wedge guard (last-resort, in-process)

Every 30 s, if state has been continuously not-`Ready` for longer than
`WEDGE_GUARD_THRESHOLD_SECONDS` (default 900 s = 15 min), the guard calls
`os.Exit(1)`. systemd's `Restart=always` respawns the binary inside the
same container.

Why exit instead of letting kubelet restart the container:
- preserves `/var/log/journal` for post-mortem (kubelet container restart
  wipes the writable layer)
- doesn't bump the kubelet restart counter
- respawn is faster (no image pull, no veth/netns re-setup)
- a fresh process re-runs `Login()` + `Connect()`, which usually clears
  daemon-level wedges (piactl/expressvpnctl IPC stuck, etc.)

The threshold is sized so a flapping watchdog (multiple reconnect failures
spaced by backoff) doesn't trip it; only a genuinely-stuck provider does.

### 3. Hub envoy outlier detection (out-of-process)

The hub envoy in the `tundler-fleet-controller` pod runs
`ConsecutiveGatewayFailure: 5` outlier detection on each tunnel pod
(`xds_snapshot.go`). When the crawler sees 5 consecutive gateway failures
through a given pod, envoy ejects it from the LB pool for a cool-off
period and steers crawl traffic to other pods. The bad pod isn't killed —
it just stops receiving traffic until it either rotates (clean exit IP)
or trips the wedge guard.

This is the **right** place to handle "this exit IP is banned" or "this
pod is temporarily slow" — far cheaper than restarting anything.

## Rotation

Two triggers, one path:

- **Hourly timer.** `MIN_ROTATION_SECONDS` (default 3600) ± 10 % jitter;
  initial offset is uniformly random in `[0, MIN_ROTATION_SECONDS)` so a
  fleet that boots together doesn't rotate in lockstep.
- **`POST /rotate`** from `tundler-fleet-controller`, itself driven by
  the crawler's per-tunnel 429 tracking. Sustained 429s on a slot trigger
  a fanout to the offending pod's `/rotate`.

Both go through `rotateIfReady`. State transitions Ready → Draining
(proxy stops accepting new CONNECTs) → Rotating (Disconnect + Connect
with up-to-`ROTATION_RETRY_MAX` location retries) → Ready / Failed.

### `/rotate` debounce

`rotateHandler` refuses a fresh rotation if the previous one completed
within `minTimeBetweenRotations` (30 s, hard-coded). Without this, a
burst of 429s on a freshly-rotated IP could trigger back-to-back
rotations that prevent the new exit IP from ever serving real traffic,
which in turn produced the rotation-storm pattern that filled the
kubelet restart counters. The debounce is server-side, so any number of
upstream clients fanning out can't bypass it.

A debounced request returns `200 OK` with a message describing the
remaining cooldown, not 429 or 409 — idempotency: the caller's intent
("please rotate") is already on the way to being satisfied by the
recent rotation.

## Environment knobs

| variable                          | default | purpose                                             |
|-----------------------------------|---------|-----------------------------------------------------|
| `TUNDLER_TUNNEL_PROVIDER`         | —       | which compiled-in provider plugin to run            |
| `BOOT_LOGIN_JITTER_SECONDS`       | 60      | random 0..N s wait before first `Login()`           |
| `EXCLUDED_LOCATIONS`              | —       | space-separated locations to filter out             |
| `TUNNEL_WATCHDOG_INTERVAL_SECONDS`| 30      | watchdog tick period                                |
| `MIN_ROTATION_SECONDS`            | 3600    | rotation cadence (± 10 % jitter)                    |
| `ROTATION_RETRY_MAX`              | 3       | per-rotation location-retry budget                  |
| `ROTATION_ATTEMPT_TIMEOUT_SECONDS`| 20      | per-attempt timeout in `connectWithRetry`           |
| `WEDGE_GUARD_THRESHOLD_SECONDS`   | 900     | non-Ready window before `os.Exit(1)` + systemd respawn |
| `TUNDLER_CLUSTER_BYPASS_CIDR`     | —       | route /16 around VPN tunnel for in-cluster traffic   |
| `POD_NAME`                        | downward| → `x-tundler-tunnel-id` response header on CONNECT   |
| `TUNDLER_TUNNEL_NODE_IP`          | —       | → `x-tundler-node-ip` response header                |

## What was removed (Phase 4)

- Sibling **envoy container** in the tunnel pod (and its bootstrap
  ConfigMap, Lua header injection, `%ENV()` workaround, xDS reconnect
  storms).
- The **`internal/xds` package** that pushed exit-IP snapshots over xDS.
  Replaced by an in-process `atomic.Value` swap (`proxy.Server.SetExitIP`)
  read by every `/handle` call — no IPC, no protobuf, no LDS/CDS update.
- The **self-monitor** that polled envoy's admin `/stats` for response-
  code rates (Trigger C). Replaced by crawler-side per-tunnel 429
  tracking that POSTs `/rotate` directly.
- The **`/livez` 503-on-wedge** logic, replaced by the wedge-guard
  goroutine (see above) so the kubelet-visible restart count stays clean.

The hub envoy in `tundler-fleet-controller` is unchanged — only the
per-tunnel-pod sibling envoy was retired.
