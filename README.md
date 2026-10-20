# Tundler

Tundler ("tunnel bundler") turns a commercial VPN subscription into
**single-purpose tunnel pods**. One Docker image per provider runs the
`tundler-tunnel` binary, which logs in, brings the VPN up, keeps it healthy,
rotates the exit IP on a schedule, and exposes the tunnel as an in-process
HTTP **CONNECT proxy**. A Kubernetes crawler fleet points each of its slots at
a tunnel pod's proxy and gets a large, diverse pool of rotating egress IPs.

Images are built by CI for every provider and published to the GitHub
Container Registry as `ghcr.io/laurentpellegrino/tundler-<provider>`
(`:latest` plus one `:<commit-sha>` tag), on every push to `main` and once a
day to pick up base-image and server-list updates. The runtime design (pod
state machine, probes, failure layers, rotation and drain) is in
[`cmd/tundler-tunnel/README.md`](cmd/tundler-tunnel/README.md).

## What a tunnel pod does

Each pod is a single container running `systemd` → `tundler-tunnel`, which:

1. **Logs in** to the provider with its pod's account (see
   [Accounts](#accounts)) and **connects** a tunnel to a randomly chosen
   allowed location.
2. Verifies the tunnel actually routes traffic out a different IP than the
   node (the **exit-IP contract test**) before reporting ready.
3. Serves an in-process **CONNECT proxy on `:8485`** — crawler traffic dialed
   through it egresses via the VPN — and a browser-impersonating forward
   proxy on `:8486`.
4. Serves an **HTTP control API on `:4242`** (`/livez`, `/readyz`, `/status`,
   `/rotate`) used by k8s probes and by clients triggering a rotation.
5. **Rotates** to a fresh exit on a time window (or on demand), draining
   in-flight connections first.
6. Self-heals via an in-process **watchdog** (reconnects when upstream dials
   start failing) and **wedge guard** (force-reconnect if stuck).

## Providers

One image per provider (`tundler-<provider>`), selected at build time. Four
integration shapes:

| Shape | Providers | How it connects |
|-------|-----------|-----------------|
| **Vendor CLI daemon** | `expressvpn`, `nordvpn`, `pia`, `warp` | drives the official Linux client/daemon |
| **OpenVPN-direct** | `cyberghost`, `fastvpn`, `ipvanish`, `ovpn`, `protonvpn`, `purevpn`, `surfshark`, `veepn`, `windscribe` | spawns `openvpn` from a baked/fetched config + credential |
| **WireGuard (wg-quick)** | `mullvad` | per-pod key + assigned address, `wg-quick up` |
| **Proxy-chain** | `tunnelbear`, `psiphon` | forwards through an upstream HTTPS/local proxy instead of a kernel tunnel (the proxy's dial-func seam) |

Vendor clients are installed by `docker/providers/<provider>/install.sh`:
ExpressVPN is pinned there (14.2.0), PIA resolves the newest Linux build
from its changelog at image build time (3.8 fallback), NordVPN and
Cloudflare WARP come from the vendors' package repositories, and the
OpenVPN/WireGuard tools come from Ubuntu. Server lists and OpenVPN configs
are refreshed daily by the `update-*` workflows and baked at build time
from GitHub release assets.

## Accounts

Every provider supports **multiple accounts**. An account is a named bag of
credential fields plus an explicit `slots` capacity (how many pods it can
serve concurrently — the provider's device/session cap made enforceable).
Pod ordinals are block-partitioned over accounts in order: accounts
`main` (slots 5) + `backup` (slots 3) serve ordinals 0-4 and 5-7. An
ordinal beyond the declared capacity is a loud boot error surfaced on
`/status` — not a login storm.

Accounts arrive as a **directory** (in the fleet: a projected Secret, kept
in sync from OpenBao via ExternalSecret):

```
/etc/tundler/accounts/
  main/
    username        # one file per field
    password
  backup/
    username
    password
```

- `TUNDLER_ACCOUNTS` (env, e.g. `main:5,backup:3`) pins account ordering +
  slots in production; without it, lexicographic directory order + an
  optional `slots` file per account (default 1) apply — name dirs
  `00-main`, `01-backup` to make order visible. Slots `0` marks a sole
  UNCAPPED account (`main:0`): it serves every ordinal, so the value
  never changes when the fleet scales.
- Local dev shortcut: `TUNDLER_ACCOUNT_<FIELD>` env vars (e.g.
  `TUNDLER_ACCOUNT_USERNAME`) synthesize a single account.
- Files, not env, on purpose: the entrypoint's line-oriented env filter
  truncates multi-line PEMs, and a projected Secret updates in place —
  credential fixes heal pods without restarts or re-logins.
- `/status` reports `account_id` and `account_source` (`dir`, `env` or
  `legacy`), so mid-migration pods are visible at a glance.

Field names per provider (also the OpenBao property names):

| Provider | Account fields |
|----------|----------------|
| expressvpn | `activation_code` |
| nordvpn | `token` |
| pia, ipvanish, ovpn, purevpn, fastvpn, veepn, tunnelbear | `username`, `password` |
| protonvpn | `username`, `password` (the OpenVPN pair, not the Proton login) |
| windscribe | `username`, `password` (the OpenVPN credential, not the account login) |
| surfshark | `username`, `password` (OpenVPN) or `private_key` (WireGuard, one key pinned per pod) |
| mullvad | `private_key`, `address` (`address6` reserved) — one device identity per Slots=1 account |
| cyberghost | `certificate`, `key`, `username`, `password` — one device profile per Slots=1 account |
| warp | none (anonymous/mdm registration) |
| psiphon | none (embedded network config) |

**Legacy env vars keep working** (deprecated, one log line at boot): the
pre-accounts variables — `PRIVATEINTERNETACCESS_USERNAME/_PASSWORD`,
`EXPRESSVPN_ACTIVATION_CODE`, `NORDVPN_TOKEN`,
`SURFSHARK_WIREGUARD_PRIVATE_KEYS` (comma pool, random pick),
per-pod `POD_<n>_MULLVAD_*` / `POD_<n>_VEEPN_*` and cyberghost's
`/etc/cyberghost/creds/POD_<n>_*` files — are synthesized into an
equivalent account pool when the accounts directory is absent, so images
and deployment manifests can roll independently: roll the image first,
then switch each provider's manifest to the accounts directory.

## Region spread (soft)

When the deployment renderer injects `TUNDLER_FLEET_SLOT_BASE` +
`TUNDLER_FLEET_SLOTS`, every pod computes the same epoch-seeded country
ordering. The provider's block start (`base / slots` of the way around
that ring) picks where the provider begins, and its pods take
consecutive countries from the ring-ordered list of countries the
provider actually offers (ordinal 0 the first, ordinal 1 the next, …),
so siblings land on distinct countries with **zero coordination** (no
peer traffic, no extra RBAC) for as long as the catalog has one to
spare. Each rotation advances a pod by `TUNDLER_FLEET_REPLICAS` (the
provider's pod count) along that list, so a pod only ever visits its
own positions and siblings with different rotation histories never
meet (without the replicas env the stride is one). It is a preference,
never a guarantee: any miss falls back to the classic uniform-random
pick, and providers with unmappable location vocabularies (city names,
`auto`) simply ignore it. `/status` exposes `fleet_slot`,
`preferred_country` and `current_country`. Absent env = feature off.

A rotation re-picks in the same country (another location when the
country has one) for up to `TUNDLER_COUNTRY_DWELL` rotations (default
4), so a big pool keeps yielding fresh exits. Upstreams meter by
prefix, so a rotation that lands in a /24 (IPv6: /48) this pod already
used within `TUNDLER_EXIT_MEMORY` (default 1h) is the spent-quota
signal: the location and its country are cooled for
`TUNDLER_BLOCKED_COOLDOWN` (default 1h), skipped by every pick,
preferred or random, the walk moves on and the rotation retries
elsewhere while it has attempts left. A pod whose whole catalog is
cooling ignores the cool-down rather than staying down. `POST /rotate` accepts `{"reason":"blocked"}` (or
`?reason=blocked`) from the crawler; it is logged, a throttled IP alone
says nothing about the pool behind it.

## Build & run

Pull a prebuilt image, or build one provider's image locally:

```bash
docker pull ghcr.io/laurentpellegrino/tundler-windscribe:latest

docker build -f docker/Dockerfile.tunnel \
    --build-arg PROVIDER=windscribe \
    -t ghcr.io/laurentpellegrino/tundler-windscribe:latest .
```

The `PROVIDER` build-arg both selects the provider's `install.sh`
(`docker/providers/<provider>/`) and compiles the binary with
`-tags provider_<provider>` so only that provider's code + embedded data is
linked. ExpressVPN builds on `ubuntu:26.04` (`--build-arg
BASE_IMAGE=ubuntu:26.04`, see the CI workflow for why); everything else on
the default `ubuntu:24.04`.

Run it. The container boots `systemd`, so it needs the cgroup tree, and
the kernel-tunnel providers need `NET_ADMIN` plus `/dev/net/tun`:

```bash
docker run --rm -d --name tundler-windscribe \
  --privileged --cap-add NET_ADMIN --device /dev/net/tun \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --cgroupns=host \
  -e TUNDLER_TUNNEL_PROVIDER=windscribe \
  -e TUNDLER_ACCOUNT_USERNAME=... -e TUNDLER_ACCOUNT_PASSWORD=... \
  -p 8485:8485 -p 4242:4242 \
  ghcr.io/laurentpellegrino/tundler-windscribe:latest

# multi-account: mount a directory instead (one subdir per account,
# one file per field — see "Accounts" above) and pin the partition:
#   -v ./accounts:/etc/tundler/accounts:ro -e TUNDLER_ACCOUNTS=main:5,backup:3
#   -e POD_NAME=tundler-tunnel-windscribe-6   # ordinal 6 → backup

# crawl through the tunnel:
curl -x http://localhost:8485 https://ipinfo.io
# check health / current exit / selected account:
curl http://localhost:4242/status
```

### Useful env knobs

| Variable | Description |
|----------|-------------|
| `TUNDLER_TUNNEL_PROVIDER` | which compiled-in provider to run (one per image) |
| `EXCLUDED_LOCATIONS` | comma-separated locations the random picker must never choose |
| `MIN_ROTATION_SECONDS` / `MAX_ROTATION_SECONDS` | rotation interval window (each interval is a fresh uniform pick; both `0` disables scheduled rotation) |
| `BOOT_LOGIN_JITTER_SECONDS` | spread simultaneous boot logins to avoid bursting the auth API |
| `TUNDLER_PROXY_PORT` | CONNECT proxy port (default `8485`) |
| `POD_NAME` / `POD_NAMESPACE` | downward-API identity; the pod's ordinal (from `POD_NAME`) selects its account |
| `TUNDLER_ACCOUNTS_DIR` | accounts directory override (default `/etc/tundler/accounts`) |
| `TUNDLER_ACCOUNTS` | ordered `<id>:<slots>` CSV pinning the ordinal→account partition (`0` = sole uncapped account) |
| `TUNDLER_FLEET_SLOT_BASE` / `TUNDLER_FLEET_SLOTS` | enable the soft region-spread preference |
| `TUNDLER_FLEET_REPLICAS` | this provider's pod count: rotation stride of the region walk (default 1) |
| `TUNDLER_COUNTRY_DWELL` | rotations a pod spends in one country before the region walk moves on (default 4, `0` = every rotation) |
| `TUNDLER_EXIT_MEMORY` | how long an exit prefix (/24, IPv6 /48) is remembered; a rotation landing in a remembered prefix cools its location and country and retries elsewhere (default `1h`, `0` disables) |
| `TUNDLER_BLOCKED_COOLDOWN` | how long a spent location and country stay skipped (default `1h`, `0` disables) |
| `TUNDLER_CLUSTER_BYPASS_CIDR` | route this CIDR around the tunnel so in-cluster traffic keeps working |
| `TUNDLER_CLUSTER_RESOLV_CONF` | resolv.conf the entrypoint saved before any VPN client could rewrite the live one (default `/run/tundler/resolv.conf`); event sinks resolve through its nameservers, so in-tunnel DNS can't break delivery; DNS over eth0 towards `TUNDLER_CLUSTER_BYPASS_CIDR` (or those nameservers when no CIDR is set) is also kept allowed at the head of the pod's OUTPUT chain (entrypoint, after every connect, and ExpressVPN's prestart), because ExpressVPN's firewall rejects port 53 to anything but its own resolver even with network lock off |

The full list is in [`cmd/tundler-tunnel/README.md`](cmd/tundler-tunnel/README.md#environment-knobs).

## HTTP control API (`:4242`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/livez` | GET | process is up |
| `/readyz` | GET | `200` only when a tunnel is connected and the exit-IP contract passed; `503` while connecting/draining/failed |
| `/status` | GET | JSON: state, current location, exit IP, tunnel age, next-rotation countdown, rotation/auth-failure counts, selected account, region preference |
| `/rotate` | POST | drain in-flight connections, disconnect, reconnect to a fresh exit |

## Extending: add a provider

1. `internal/provider/<name>/<name>.go` — implement the `provider.VPNProvider`
   interface (`Login`/`Logout`/`LoggedIn`, `Connect`/`Disconnect`/`Connected`,
   `Locations`, `ActiveLocation`, `Status`, `Version`). Rotation is just the
   binary calling `Disconnect` then `Connect` again. Proxy-chain providers also
   take the in-process proxy via an `AttachProxy(*proxy.Server)` method and
   install a dialer with `SetDialer`.
2. `internal/provider/register/register_<name>.go` — build-tagged blank import:

   ```go
   //go:build provider_<name>

   package register

   import _ "github.com/laurentpellegrino/tundler/internal/provider/<name>"
   ```

3. `docker/providers/<name>/install.sh` (+ `configure.sh`) — install the VPN
   client / bake any config; keep it self-contained.
4. Add `<name>` to the allow-list in `docker/Dockerfile.tunnel`, the matrix in
   `.github/workflows/docker-image.yml`, and the env-passthrough regex in
   `docker/services/tundler-entrypoint.sh`.
5. Resolve credentials through the accounts package — `accounts.Current(name)`
   + `acct.Require(accounts.Field…)` — and add the provider's field names to
   the "Account fields" table above. Only providers that predate the accounts
   model register a legacy env shim; a new provider doesn't need one.

## Contributing

Pull requests are welcome.
