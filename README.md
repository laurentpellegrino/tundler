# Tundler

Tundler ("tunnel bundler") turns a commercial VPN subscription into
**single-purpose tunnel pods**. One Docker image per provider runs the
`tundler-tunnel` binary, which signs in, brings the VPN up, keeps it healthy,
changes the exit IP on a schedule, and exposes the tunnel as a local HTTP
**proxy**. Point many clients at many pods and you get a large, constantly
rotating pool of egress IP addresses.

CI builds an image for every provider and publishes it to the GitHub Container
Registry as `ghcr.io/laurentpellegrino/tundler-<provider>` (`:latest` plus a
`:<commit-sha>` tag), on every push to `main` and once a day to pick up
base-image and server-list updates.

The deep runtime design (state machine, health probes, self-healing, rotation)
lives in [`cmd/tundler-tunnel/README.md`](cmd/tundler-tunnel/README.md). This
page is the overview and the configuration reference.

## What a pod does

Each pod is one container running `systemd` → `tundler-tunnel`, which:

1. **Signs in** with the pod's account (see [Accounts](#accounts)) and
   **connects** to a random allowed location.
2. **Checks the exit** really routes out a different IP than the node before
   reporting ready.
3. **Serves two proxies**: a plain CONNECT proxy on `:8485` (traffic sent
   through it leaves via the VPN) and a browser-impersonating forward proxy on
   `:8486` (fetches a URL upstream with a real browser TLS fingerprint; one
   preset per pod).
4. **Answers a control API** on `:4242` (`/livez`, `/readyz`, `/status`,
   `/rotate`).
5. **Rotates** to a fresh exit on a timer or on demand, draining open
   connections first.
6. **Self-heals**: reconnects when traffic starts failing, and force-reconnects
   if it gets stuck.

## Providers

One image per provider, chosen at build time. Providers fall into six
connection shapes:

| Shape | Providers |
|-------|-----------|
| **Vendor CLI / daemon** | `expressvpn`, `nordvpn`, `pia`, `warp` |
| **OpenVPN (direct)** | `cyberghost`, `fastvpn`, `ipvanish`, `norton`, `ovpn`, `protonvpn`, `purevpn`, `surfshark`, `veepn`, `windscribe` |
| **OpenVPN + native API** | `hidemyass` |
| **WireGuard (`wg-quick`)** | `mullvad` |
| **WireGuard (vendor service)** | `hideme` |
| **Proxy chain** | `psiphon`, `tunnelbear` |

Provider notes (only where it matters):

- **fastvpn**, **ipvanish** — dial through Cloudflare WARP by default
  (`*_TRANSPORT=warp`), because the vendor rejects datacenter source IPs; set
  `*_TRANSPORT=direct` on residential hosts.
- **norton** — the Norton VPN / SurfEasy (Gen Digital) backend; a per-device
  OpenVPN username and password, the static CA baked in.
- **protonvpn** — connects against Proton's server catalog; `PROTON_FEATURE_FILTER`
  narrows the pool to a tier such as `securecore`.

Vendor clients are installed by `docker/providers/<provider>/install.sh`
(ExpressVPN pinned to 14.2.0; PIA resolved at build time; NordVPN and WARP from
the vendor repositories; OpenVPN/WireGuard from Ubuntu). Server lists and
configs are refreshed daily by the `update-*` workflows and baked at build
time.

## Accounts

Every provider supports **multiple accounts**. An account is a named set of
credential fields plus a `slots` number — how many pods it may serve at once
(the provider's device limit, made enforceable). Pods are assigned to accounts
by ordinal: `main:5,backup:3` gives ordinals 0-4 to `main` and 5-7 to `backup`.
A pod past the last slot fails loudly at boot instead of starting a login
storm.

Accounts are read from a **directory** (one subdirectory per account, one file
per field):

```
/etc/tundler/accounts/
  main/
    username
    password
  backup/
    username
    password
```

In the fleet this directory is a projected Secret kept in sync from OpenBao, so
a credential fix heals pods in place with no restart. For local development,
`TUNDLER_ACCOUNT_<FIELD>` (e.g. `TUNDLER_ACCOUNT_USERNAME`) synthesizes a single
account. `/status` shows the chosen `account_id` and `account_source`.

**Account fields per provider** (also the OpenBao property names), sorted by
provider:

| Provider | Fields |
|----------|--------|
| `cyberghost` | `certificate`, `key`, `username`, `password` (one device per `slots=1` account) |
| `expressvpn` | `activation_code` |
| `fastvpn` | `username`, `password` |
| `hideme` | `username`, `password` (account login; exchanged for a token at each start) |
| `hidemyass` | `username`, `password` (account email/password; device credentials fetched automatically) |
| `ipvanish` | `username`, `password` |
| `mullvad` | `private_key`, `address` (one device per `slots=1` account) |
| `nordvpn` | `token` |
| `norton` | `username`, `password` (the per-device OpenVPN credential, not the Norton account login) |
| `ovpn` | `username`, `password` |
| `pia` | `username`, `password` |
| `protonvpn` | `username`, `password` (the OpenVPN pair, not the Proton login) |
| `psiphon` | none (embedded config) |
| `purevpn` | `username`, `password` |
| `surfshark` | `username`, `password` (OpenVPN) or `private_key` (WireGuard) |
| `tunnelbear` | `username`, `password` |
| `veepn` | `username`, `password` |
| `warp` | none (anonymous registration) |
| `windscribe` | `username`, `password` (the OpenVPN credential, not the account login) |

Older single-account environment variables (`NORDVPN_TOKEN`,
`EXPRESSVPN_ACTIVATION_CODE`, …) still work and log a one-line deprecation at
boot, so images and manifests can be rolled independently.

## Region spread (soft)

When a pod can see the fleet layout (the `vpn-providers.yaml` mounted at
`/etc/tundler/fleet/`, or the `TUNDLER_FLEET_*` env fallback), every pod
computes the same country ordering and each sibling takes a different country —
with no coordination between pods. It is a **preference, not a guarantee**: any
gap falls back to a uniform random pick.

On top of that, each pod avoids reusing an exit it recently used: a rotation
landing in a /24 (or IPv6 /48) seen within `TUNDLER_EXIT_MEMORY` is treated as
spent, so that location is cooled and the rotation retries elsewhere. A crawler
can also tell a pod which exits to steer clear of via `POST /rotate` (see the
[control API](#http-control-api-4242) and the detailed README). With no fleet
file and no env, the feature is simply off.

## Build & run

Pull a prebuilt image, or build one provider locally:

```bash
docker pull ghcr.io/laurentpellegrino/tundler-windscribe:latest

docker build -f docker/Dockerfile.tunnel \
    --build-arg PROVIDER=windscribe \
    -t ghcr.io/laurentpellegrino/tundler-windscribe:latest .
```

The `PROVIDER` build-arg picks the provider's `install.sh` and compiles only
that provider's code (`-tags provider_<provider>`). ExpressVPN needs
`--build-arg BASE_IMAGE=ubuntu:26.04`; everything else uses the default
`ubuntu:24.04`.

Run it. The container boots `systemd` (so it needs the cgroup tree), and
kernel-tunnel providers need `NET_ADMIN` and `/dev/net/tun`:

```bash
docker run --rm -d --name tundler-windscribe \
  --privileged --cap-add NET_ADMIN --device /dev/net/tun \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --cgroupns=host \
  -e TUNDLER_TUNNEL_PROVIDER=windscribe \
  -e TUNDLER_ACCOUNT_USERNAME=... -e TUNDLER_ACCOUNT_PASSWORD=... \
  -p 8485:8485 -p 4242:4242 \
  ghcr.io/laurentpellegrino/tundler-windscribe:latest

# crawl through the tunnel:
curl -x http://localhost:8485 https://www.cloudflare.com/cdn-cgi/trace
# check health / current exit / selected account:
curl http://localhost:4242/status
```

For multiple accounts, mount a directory instead of the `TUNDLER_ACCOUNT_*`
shortcuts (`-v ./accounts:/etc/tundler/accounts:ro -e
TUNDLER_ACCOUNTS=main:5,backup:3`) and set `POD_NAME` so the ordinal picks the
account.

## Environment variables

The common knobs, sorted by name. The full list is in
[`cmd/tundler-tunnel/README.md`](cmd/tundler-tunnel/README.md#environment-knobs).
Durations accept Go syntax (`1h`, `30m`); `0` disables where noted.

| Variable | What it does |
|----------|--------------|
| `BOOT_LOGIN_JITTER_SECONDS` | Spread simultaneous boot logins so they don't burst the auth API. |
| `EXCLUDED_LOCATIONS` | Comma-separated locations the picker must never choose. |
| `FASTVPN_TRANSPORT` | `warp` (default, OpenVPN over WARP) or `direct` (plain UDP); fastvpn only. |
| `IPVANISH_TRANSPORT` | `warp` (default, OpenVPN over WARP) or `direct` (plain vendor config); ipvanish only. |
| `MIN_ROTATION_SECONDS` / `MAX_ROTATION_SECONDS` | Rotation interval window; both `0` turns scheduled rotation off. |
| `POD_NAME` / `POD_NAMESPACE` | Pod identity; the ordinal in `POD_NAME` selects the account. |
| `PROTON_FEATURE_FILTER` | Narrow Proton's server pool to a tier (e.g. `securecore`); protonvpn only. |
| `TUNDLER_ACCOUNTS` | Ordered `<id>:<slots>` list pinning the ordinal → account mapping (`0` = one uncapped account). |
| `TUNDLER_ACCOUNTS_DIR` | Accounts directory (default `/etc/tundler/accounts`). |
| `TUNDLER_AUTH_FAILURE_BACKOFF_SECONDS` | How long to hold all connects once credentials are rejected repeatedly; doubles up to 24 h, cleared by a success (default `3600`). |
| `TUNDLER_AUTH_FAILURES_BEFORE_HOLD` | Credential rejections in a row that trigger that hold (default `3`); fewer just skips the offending server. |
| `TUNDLER_BLOCKED_COOLDOWN` | How long a spent location/country stays skipped (default `1h`). |
| `TUNDLER_CLUSTER_BYPASS_CIDR` | Keep traffic to this CIDR off the tunnel so in-cluster calls still work. |
| `TUNDLER_CLUSTER_RESOLV_CONF` | Saved resolv.conf used for event delivery and DNS kept allowed around the tunnel (default `/run/tundler/resolv.conf`). |
| `TUNDLER_COUNTRY_DWELL` | Rotations spent in one country before the region walk moves on (default `4`). |
| `TUNDLER_EXIT_MEMORY` | How long a used exit prefix is remembered and avoided (default `1h`). |
| `TUNDLER_FAILING_LOCATION_HOLD` | How long a failing location is skipped; doubles up to 7 days, forgotten on a success (default `24h`). |
| `TUNDLER_FLEET_LAYOUT` | Fleet topology file for region spread (default `/etc/tundler/fleet/vpn-providers.yaml`). |
| `TUNDLER_FLEET_REPLICAS` | With the static fallback: this provider's pod count (the region-walk stride). |
| `TUNDLER_FLEET_SLOT_BASE` / `TUNDLER_FLEET_SLOTS` | Static fallback for region spread when no topology file is mounted. |
| `TUNDLER_IMPERSONATE_PROFILE` | Pin the browser fingerprint for the `:8486` proxy (`Chrome-133`, `Firefox-120`, `Safari-16-0`, `golang`); default is per-pod. |
| `TUNDLER_PROXY_PORT` | CONNECT proxy port (default `8485`). |
| `TUNDLER_REFUSED_MEMORY` | How long an exit prefix the upstream refused (`/rotate` `reason=banned`) is avoided (default `24h`). |
| `TUNDLER_THROTTLE_BACKOFF_SECONDS` | How long to hold connects after a "too many attempts" refusal; doubles up to 30 min (default `300`). |
| `TUNDLER_TUNNEL_PROVIDER` | Which compiled-in provider to run (one per image). |

## HTTP control API (`:4242`)

| Endpoint | Method | What it returns |
|----------|--------|-----------------|
| `/livez` | GET | `200` while the process is up. |
| `/readyz` | GET | `200` only when the tunnel is connected and the exit check passed; `503` otherwise. |
| `/rotate` | POST | Drains, disconnects and reconnects to a fresh exit. |
| `/status` | GET | JSON: state, location, exit IP, tunnel age, next-rotation countdown, counts, account, region preference. |

## Add a provider

1. `internal/provider/<name>/<name>.go` — implement the `provider.VPNProvider`
   interface (`Login`/`Logout`/`LoggedIn`, `Connect`/`Disconnect`/`Connected`,
   `Locations`, `ActiveLocation`, `Status`, `Version`). Rotation is just
   `Disconnect` then `Connect`.
2. `internal/provider/register/register_<name>.go` — a build-tagged blank
   import:

   ```go
   //go:build provider_<name>

   package register

   import _ "github.com/laurentpellegrino/tundler/internal/provider/<name>"
   ```

3. `docker/providers/<name>/install.sh` (+ `configure.sh`) — install the client
   / bake any config.
4. Add `<name>` to the allow-list in `docker/Dockerfile.tunnel`, the matrix in
   `.github/workflows/docker-image.yml`, and the env regex in
   `docker/services/tundler-entrypoint.sh`.
5. Resolve credentials with `accounts.Current(name)` + `acct.Require(...)`, and
   add the provider to the **Providers** and **Account fields** tables above.

## Contributing

Pull requests are welcome.
