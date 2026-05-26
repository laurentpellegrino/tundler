# tundler-tunnel

Single-container, single-provider VPN runtime that runs in each
per-provider tunnel pod of the VPN-hub architecture. One Go runtime
owns the VPN provider, the HTTP CONNECT proxy, the control API, and
the pod lifecycle.

## Process layout inside the pod

```
systemd (PID 1, from image entrypoint)
└─ tundler-tunnel.service              Restart=always
   └─ tundler-tunnel (single Go binary)
      ├─ goroutine: HTTP control API  (:4242 /livez /readyz /status /rotate)
      ├─ goroutine: CONNECT proxy     (:8485 — outbound HTTP CONNECT data plane)
      ├─ goroutine: watchdog          (tunnel-health poller)
      ├─ goroutine: rotator           (windowed random rotation + /rotate trigger)
      ├─ goroutine: wedge guard       (restart trigger)
      └─ provider-specific subprocesses (piactl monitor / expressvpnctl background)
```

Crawler traffic flow:

```
crawler slot  ──HTTP CONNECT──▶  tundler-tunnel pod  :8485   (Go CONNECT proxy)
   pinned to one pod via            │  bidirectional io.Copy through the VPN
   per-pod headless DNS             ▼
                              internet via tun0
```

Each crawler slot is deterministically pinned to one tunnel pod (via
the per-provider headless Service's per-pod DNS) and resolves directly
to that pod's `:8485`. There is no shared LB or aggregator in front of
the tunnel pods.

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

| probe     | path     | failure → action          | what it catches                                                                  |
|-----------|----------|---------------------------|----------------------------------------------------------------------------------|
| startup   | `/readyz`| container restart         | wedged-at-boot: pod never reaches `state == Ready` within ~10 min                |
| liveness  | `/livez` | container restart         | Go HTTP server actually hung (the act of serving 200 IS the signal)              |
| readiness | `/readyz`| removed from LB pool      | rotation in progress, brief Failed window, anything not `state == Ready`         |

`/livez` returns 200 unconditionally. VPN-state policy lives elsewhere:

- **Startup probe** (kubelet, `failureThreshold × periodSeconds ≈ 10 min`)
  catches *wedged-at-boot*. When the provider daemon (e.g. `expressvpnd`)
  is stuck, the binary can't reach Ready no matter how many times systemd
  respawns it — the daemon is in its own systemd unit and survives binary
  restarts. Only a fresh container rootfs reliably clears it, which is
  what kubelet's container restart does.
- **Wedge guard** (in-process, see below) catches *runtime wedges* — pod
  was Ready, then lost it for too long. Exits the binary so systemd
  respawns it inside the same container; preserves the journal and avoids
  the container-restart counter.

Keeping `/livez` trivial means the only thing that triggers a
*liveness*-driven container restart is the Go HTTP server itself hanging
— a real "process is hung" signal.

## Failure-handling layers

Two in-process layers cover transient and wedged failures. There is
no external supervisor — the pod is self-managed.

### 1. Watchdog (in-process)

Every `TUNNEL_WATCHDOG_INTERVAL_SECONDS` (default 30 s) the watchdog
checks `provider.Connected()` when state is `Ready`. If the tunnel
dropped, it reconnects via `connectTunnel`.

The watchdog goroutine stays alive across failures. A failed
reconnect sets state to `Failed`, sleeps with exponential backoff
(5 s → 10 s → 20 s → 40 s → 60 s cap), and tries again on the next
tick. It also recovers from `Failed`, not just from
`Ready`-with-tunnel-down, so recovery happens within a few backoff
cycles of the daemon becoming responsive again.

### 2. Wedge guard (in-process)

Every 30 s, if state has been continuously not-`Ready` for longer
than `WEDGE_GUARD_THRESHOLD_SECONDS` (default 900 s = 15 min), the
guard calls `os.Exit(1)`. systemd's `Restart=always` respawns the
binary inside the same container.

Respawning via systemd (rather than via a kubelet container restart)
keeps `/var/log/journal` intact for post-mortem, leaves the
kubelet-visible restart count quiet, and avoids the cost of
image-pull and netns re-setup. A fresh process re-runs `Login()` +
`Connect()`, which clears most daemon-level wedges (piactl /
expressvpnctl IPC stuck, stale session tokens, etc.).

The 15 min threshold accommodates the watchdog's full backoff
sequence, so a flapping recovery doesn't trip it; only a
genuinely-stuck provider does.

## Rotation

Two triggers, one path:

- **Random-window timer.** Each interval is a fresh uniform random
  pick from `[MIN_ROTATION_SECONDS, MAX_ROTATION_SECONDS]` (defaults
  7200..14400 — 2 h to 4 h). The initial boot offset is sampled from
  the same window so a fleet that boots together is spread across the
  full window from the first rotation onward — no synchronized
  stampede after one min-window elapses either. Set
  `MIN_ROTATION_SECONDS == MAX_ROTATION_SECONDS` for a fixed cadence.
- **`POST /rotate`** from the crawler slot that owns this pod. The
  slot tracks 429s and consecutive failures via its own AIMD token
  bucket; when it decides to rotate, it POSTs straight to this pod's
  `:4242/rotate` via the headless-service DNS — no aggregator hop.

Both go through `rotateIfReady`. State transitions
Ready → Draining (proxy stops accepting new CONNECTs) →
Rotating (Disconnect + Connect with up to `ROTATION_RETRY_MAX`
location retries) → Ready / Failed.

### `/rotate` debounce

`rotateHandler` enforces a `minTimeBetweenRotations` cooldown (30 s,
hard-coded) measured from the previous rotation's completion. The
debounce is server-side, so any number of upstream clients fanning
out get collapsed into a single rotation per window.

A debounced request returns `200 OK` with a message describing the
remaining cooldown, not 429 or 409 — idempotency: the caller's
intent ("please rotate") is already on the way to being satisfied
by the recent rotation.

## HTTP control API (`:4242`)

| method | path      | response                                                                |
|--------|-----------|-------------------------------------------------------------------------|
| GET    | `/livez`  | `200` (always)                                                          |
| GET    | `/readyz` | `200` iff `state == Ready`, else `503`                                  |
| GET    | `/status` | JSON snapshot (state, current_location, current_exit_ip, last_rotation) |
| POST   | `/rotate` | `202` accepted, `200` debounced/idempotent, `409` problem-details       |

## CONNECT proxy (`:8485`)

In-process Go HTTP/1.1 CONNECT proxy. Each accepted CONNECT:

1. parses the `CONNECT host:port HTTP/1.1` line
2. dials `host:port` from inside the pod's net namespace (so the
   dial goes through the VPN tun0)
3. writes `HTTP/1.1 200 Connection established` plus tundler
   response headers (`x-tundler-tunnel-id`, `x-tundler-exit-ip`,
   `x-tundler-node-ip`)
4. bidirectional `io.Copy` until either side closes or
   `maxTunnelDuration` (10 min) elapses

A per-process semaphore caps concurrent tunnels at 2000.
`SetExitIP(string)` is an `atomic.Value` swap so rotations update the
response-header IP without locking.

## Environment knobs

| variable                          | default | purpose                                                    |
|-----------------------------------|---------|------------------------------------------------------------|
| `TUNDLER_TUNNEL_PROVIDER`         | —       | which compiled-in provider plugin to run                   |
| `BOOT_LOGIN_JITTER_SECONDS`       | 60      | random 0..N s wait before first `Login()`                  |
| `EXCLUDED_LOCATIONS`              | —       | space-separated locations to filter out                    |
| `TUNNEL_WATCHDOG_INTERVAL_SECONDS`| 30      | watchdog tick period                                       |
| `MIN_ROTATION_SECONDS`            | 7200    | rotation cadence: lower bound of uniform window (2 h)      |
| `MAX_ROTATION_SECONDS`            | 14400   | rotation cadence: upper bound of uniform window (4 h)      |
| `ROTATION_RETRY_MAX`              | 3       | per-rotation location-retry budget                         |
| `ROTATION_ATTEMPT_TIMEOUT_SECONDS`| 20      | per-attempt timeout in `connectWithRetry`                  |
| `WEDGE_GUARD_THRESHOLD_SECONDS`   | 900     | non-Ready window before `os.Exit(1)` + systemd respawn     |
| `TUNDLER_CLUSTER_BYPASS_CIDR`     | —       | route /16 around VPN tunnel for in-cluster traffic         |
| `POD_NAME`                        | downward| → `x-tundler-tunnel-id` response header on CONNECT         |
| `TUNDLER_TUNNEL_NODE_IP`          | —       | → `x-tundler-node-ip` response header                      |
