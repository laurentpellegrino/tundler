# Tundler

Tundler ("tunnel bundler") turns a commercial VPN provider into a **single-purpose
tunnel pod**: one Docker image per provider, each running the `tundler-tunnel`
binary which brings up the VPN, keeps it healthy, rotates its exit IP on a
schedule, and exposes the tunnel as an in-process HTTP **CONNECT proxy**.

It was built to give a Kubernetes crawler fleet a large, diverse pool of
rotating egress IPs: the crawler points each of its slots at a tunnel pod's
proxy and the pod handles everything VPN-related behind it.

> **Architecture note.** Tundler used to be a single container that bundled
> *all* providers behind one REST API + Envoy + network-namespace isolation.
> That model is gone. Today each provider is its own image, the proxy is
> in-process (no Envoy), and everything runs in the pod's main network
> namespace. The detailed runtime design is in
> [`cmd/tundler-tunnel/README.md`](cmd/tundler-tunnel/README.md).

## What a tunnel pod does

Each pod is a single container running `systemd` → `tundler-tunnel`, which:

1. **Logs in** to the provider with its pod's account (see
   [Accounts](#accounts)) and **connects** a tunnel to a randomly chosen
   allowed location.
2. Verifies the tunnel actually routes traffic out a different IP than the
   node (the **exit-IP contract test**) before reporting ready.
3. Serves an in-process **CONNECT proxy on `:8485`** — crawler traffic dialed
   through it egresses via the VPN.
4. Serves an **HTTP control API on `:4242`** (`/livez`, `/readyz`, `/status`,
   `/rotate`) used by k8s probes and by clients triggering a rotation.
5. **Rotates** to a fresh exit on a time window (or on demand), draining
   in-flight connections first.
6. Self-heals via an in-process **watchdog** (reconnects when upstream dials
   start failing) and **wedge guard** (force-reconnect if stuck).

See the design doc for the pod state machine, probe semantics, failure layers,
rotation/drain, and the full env-knob list.

## Providers

One image per provider (`tundler-<provider>`), selected at build time. Four
integration shapes:

| Shape | Providers | How it connects |
|-------|-----------|-----------------|
| **Vendor CLI daemon** | `expressvpn`, `nordvpn`, `pia`, `warp` | drives the official Linux client/daemon |
| **OpenVPN-direct** | `cyberghost`, `fastvpn`, `ipvanish`, `ovpn`, `protonvpn`, `purevpn`, `surfshark`, `veepn`, `windscribe` | spawns `openvpn` from a baked/fetched config + credential |
| **WireGuard (wg-quick)** | `mullvad` | per-pod key + assigned address, `wg-quick up` |
| **Proxy-chain** | `tunnelbear`, `psiphon` | forwards through an upstream HTTPS/local proxy instead of a kernel tunnel (the proxy's dial-func seam) |

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
  `00-main`, `01-backup` to make order visible.
- Local dev shortcut: `TUNDLER_ACCOUNT_<FIELD>` env vars (e.g.
  `TUNDLER_ACCOUNT_USERNAME`) synthesize a single account.
- Files, not env, on purpose: the entrypoint's line-oriented env filter
  truncates multi-line PEMs (the bug that once forced cyberghost's
  bespoke `/etc/cyberghost/creds` path), and a projected Secret updates
  in place — credential fixes heal pods without restarts or re-logins.

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
and deployment manifests can roll independently.

## Region spread (soft)

When the deployment renderer injects `TUNDLER_FLEET_SLOT_BASE` +
`TUNDLER_FLEET_SLOTS`, each pod derives a fleet-unique slot
(`base + ordinal`) and walks a shared epoch-seeded country ordering from
its own offset, preferring the first country its provider offers — so
tunnels spread across distinct countries with **zero coordination** (no
peer traffic, no extra RBAC). It is a preference, never a guarantee:
any miss falls back to the classic uniform-random pick, and providers
with unmappable location vocabularies (city names, `auto`) simply ignore
it. `/status` exposes `fleet_slot`, `preferred_country` and
`current_country`. Absent env = feature off.

## Build & run

Build one provider's image:

```bash
docker build -f docker/Dockerfile.tunnel \
    --build-arg PROVIDER=windscribe \
    -t laurentpellegrino/tundler-windscribe:latest .
```

The `PROVIDER` build-arg both selects the provider's `install.sh`
(`docker/providers/<provider>/`) and compiles the binary with
`-tags provider_<provider>` so only that provider's code + embedded data is
linked.

Run it (needs `NET_ADMIN` and `/dev/net/tun` for the kernel-tunnel providers):

```bash
docker run --rm \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -e WINDSCRIBE_USERNAME=... -e WINDSCRIBE_PASSWORD=... \
  -p 8485:8485 -p 4242:4242 \
  laurentpellegrino/tundler-windscribe:latest

# crawl through the tunnel:
curl -x http://localhost:8485 https://example.com
# check health / current exit:
curl http://localhost:4242/status
```

### Useful env knobs

| Variable | Description |
|----------|-------------|
| `EXCLUDED_LOCATIONS` | comma-separated locations the random picker must never choose |
| `MIN_ROTATION_SECONDS` / `MAX_ROTATION_SECONDS` | rotation interval window (each interval is a fresh uniform pick) |
| `BOOT_LOGIN_JITTER_SECONDS` | spread simultaneous boot logins to avoid bursting the auth API |
| `TUNDLER_PROXY_PORT` | CONNECT proxy port (default `8485`) |
| `POD_NAME` / `POD_NAMESPACE` | downward-API identity; the pod's ordinal (from `POD_NAME`) selects its account |
| `TUNDLER_ACCOUNTS_DIR` | accounts directory override (default `/etc/tundler/accounts`) |
| `TUNDLER_ACCOUNTS` | ordered `<id>:<slots>` CSV pinning the ordinal→account partition |
| `TUNDLER_FLEET_SLOT_BASE` / `TUNDLER_FLEET_SLOTS` | enable the soft region-spread preference |

The full list is in [`cmd/tundler-tunnel/README.md`](cmd/tundler-tunnel/README.md#environment-knobs).

## HTTP control API (`:4242`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/livez` | GET | process is up |
| `/readyz` | GET | `200` only when a tunnel is connected and the exit-IP contract passed; `503` while connecting/draining/failed |
| `/status` | GET | JSON: state, current location, exit IP, tunnel age, next-rotation countdown, rotation/auth-failure counts |
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
5. Document the credential env vars in the tables above.

## Contributing

Pull requests are welcome.
