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

1. **Logs in** to the provider (env-supplied credentials) and **connects** a
   tunnel to a randomly chosen allowed location.
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

Credentials come from environment variables (in the fleet, injected from
OpenBao via ExternalSecret). Most providers share one account credential
across pods; a few are **per-pod** because each pod needs its own
session/key/device:

| Provider | Credential env |
|----------|----------------|
| expressvpn | `EXPRESSVPN_ACTIVATION_CODE` |
| nordvpn | `NORDVPN_TOKEN` |
| pia | `PRIVATEINTERNETACCESS_USERNAME` / `_PASSWORD` |
| ipvanish | `IPVANISH_USERNAME` / `_PASSWORD` |
| ovpn | `OVPN_USERNAME` / `_PASSWORD` |
| purevpn | `PUREVPN_USERNAME` / `_PASSWORD` |
| fastvpn | `FASTVPN_USERNAME` / `_PASSWORD` |
| protonvpn | `PROTON_OPENVPN_USERNAME` / `_PASSWORD` |
| surfshark | `SURFSHARK_OPENVPN_USERNAME` / `_PASSWORD` (or `SURFSHARK_WIREGUARD_PRIVATE_KEYS` + `SURFSHARK_PROTOCOL=wireguard`) |
| windscribe | `WINDSCRIBE_USERNAME` / `_PASSWORD` (the OpenVPN credential, not the account login) |
| tunnelbear | `TUNNELBEAR_USERNAME` / `_PASSWORD` |
| mullvad *(per-pod)* | `POD_<n>_MULLVAD_PRIVATE_KEY` / `_ADDRESS` |
| cyberghost *(per-pod)* | `POD_<n>_CERTIFICATE` / `_KEY` / `_USERNAME` / `_PASSWORD` |
| veepn *(per-pod)* | `POD_<n>_VEEPN_USERNAME` / `_PASSWORD` (each device credential = one connection slot) |
| warp | none (anonymous registration) |
| psiphon | none (embedded network config) |

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
curl -x http://localhost:8485 https://ipinfo.io
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
| `POD_NAME` / `POD_NAMESPACE` | downward-API identity; per-pod providers derive their ordinal from `POD_NAME` |

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
