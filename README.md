# Tundler

Tundler ("tunnel bundler") packages a small REST API in a Docker image to manage multiple VPN providers.
It can rotate tunnels on demand and exposes an HTTP proxy routed through the active VPN.

Unlike other solutions, it depends as much as possible on the VPN providers’ official client libraries
to minimise breakage and remains stateless on its own.

## Features

- REST API on port `4242` for controlling VPN connections.
- ExpressVPN, IPVanish, Mullvad, NordVPN, Private Internet Access (PIA), Proton VPN and Surfshark support out of the box.
- Optional HTTP proxy on port `8484` with Envoy-based HTTP/HTTPS support.
- YAML configuration file for location filtering and debug mode.
- Easily extensible to add new providers.
- Sidecar plugins can add non-core API features under `/plugins/...`.

## Architecture

Tundler uses Linux network namespaces to provide VPN proxy functionality while maintaining API accessibility.
The system consists of two isolated network environments within a Docker container:

### Network Architecture Diagram

```
                                 HOST SYSTEM
        ┌────────────────────────────────────────────────────────────┐
        │  curl --proxy localhost:8484 example.com                   │
        └──────────────────────┬─────────────────────────────────────┘
                               │ HTTP/HTTPS requests
                               ▼
    ┌────────────────────────────────────────────────────────────────────┐
    │                           DOCKER CONTAINER                         │
    │                                                                    │
    │   ┌───────────────── DEFAULT NAMESPACE ────────────────────────┐   │
    │   │                                                            │   │
    │   │  ┌─────────────┐   ┌─────────────────┐  ┌──────────────┐  │   │
    │   │  │ Tundler API │   │   Envoy Proxy   │  │  Docker DNS  │  │   │
    │   │  │    :4242    │   │  :8484 (envoy)  │  │  (1.1.1.1)   │  │   │
    │   │  └─────────────┘   └────────┬────────┘  └──────▲───────┘  │   │
    │   │                             │                   │ DNS      │   │
    │   │            UID-based mark ──┤  DNS queries ─────┘          │   │
    │   │            (fwmark 200)     │  exempt from VPN routing     │   │
    │   │                             ▼                              │   │
    │   │        ┌─────────────────────────────────────┐             │   │
    │   │        │             vpn-host                │             │   │
    │   │        │          172.18.0.1/30              │             │   │
    │   │        │        (veth interface)             │             │   │
    │   │        └─────────────────┬───────────────────┘             │   │
    │   └──────────────────────────┼─────────────────────────────────┘   │
    │                              │ virtual ethernet pair               │
    │                              ▼                                     │
    │   ┌──────────────── VPN NAMESPACE (vpnns) ─────────────────────┐   │
    │   │                                                            │   │
    │   │        ┌─────────────────────────────────────┐             │   │
    │   │        │         vpn-ns + MASQUERADE          │             │   │
    │   │        │           172.18.0.2/30             │             │   │
    │   │        │         (veth interface)            │             │   │
    │   │        └─────────────────────────────────────┘             │   │
    │   │                                                            │   │
    │   │  ┌──────────────┐   ┌────────────┐   ┌──────────────┐      │   │
    │   │  │  ExpressVPN  │   │    ...     │   │   NordVPN    │      │   │
    │   │  │   Service    │   │            │   │   Service    │      │   │
    │   │  │              │   │            │   │              │      │   │
    │   │  │  ┌────────┐  │   │            │   │  ┌────────┐  │      │   │
    │   │  │  │  tun0  │  │   │            │   │  │nordlynx│  │      │   │
    │   │  │  │   IF   │  │   │            │   │  │   IF   │  │      │   │
    │   │  │  └────────┘  │   │            │   │  └────────┘  │      │   │
    │   │  └──────────────┘   └────────────┘   └──────────────┘      │   │
    │   │                                │                           │   │
    │   └────────────────────────────────┼───────────────────────────┘   │
    │                                    │ VPN tunnel to internet        │
    │                                    ▼                               │
    └────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
                                ┌─────────────────┐
                                │    INTERNET     │
                                │   (VPN Server)  │
                                └─────────────────┘
```

### How Traffic Flows

1. **Proxy requests**: Client connects to Envoy on port 8484. Envoy resolves the
   upstream hostname, then opens a connection to the upstream server. All Envoy
   traffic is routed through the veth pair into vpnns and forwarded through the
   active VPN tunnel. By default, DNS queries are resolved outside the tunnel for
   lower latency. Set `TUNDLER_VPN_DNS=true` to also route DNS through the tunnel
   for full privacy (see [Environment variables](#environment-variables)).

2. **API requests**: The Tundler REST API on port 4242 stays in the default
   namespace and is always reachable regardless of VPN state.

## Getting Started

### Build the image

```bash
docker/build.sh
```

### Run the container

Credentials can be provided via environment variables or a `.env` file at the project root:

```bash
# Option 1: Environment variables
EXPRESSVPN_ACTIVATION_CODE=<code> \
IPVANISH_USERNAME=<username> \
IPVANISH_PASSWORD=<password> \
MULLVAD_ACCOUNT_NUMBER=<account> \
NORDVPN_TOKEN=<token> \
PRIVATEINTERNETACCESS_USERNAME=<username> \
PRIVATEINTERNETACCESS_PASSWORD=<password> \
PROTON_OPENVPN_USERNAME=<username> \
PROTON_OPENVPN_PASSWORD=<password> \
SURFSHARK_OPENVPN_USERNAME=<username> \
SURFSHARK_OPENVPN_PASSWORD=<password> \
docker/run.sh

# Option 2: .env file (automatically loaded by run.sh)
cat > .env << 'EOF'
NORDVPN_TOKEN=<token>
MULLVAD_ACCOUNT_NUMBER=<account>
EOF
docker/run.sh
```

The API will be reachable on port `4242` and the HTTP proxy on `8484`.

By default, VPN providers run inside their own network namespace.
The `TUNDLER_NETNS` environment variable specifies the namespace name
(defaults to `vpnns`). VPN daemons are launched in that namespace using
systemd overrides, while the REST API and proxy stay in the main namespace so they 
remain reachable even when the VPN changes routing.

#### Environment variables

##### Provider credentials

| Provider                      | Variables                                                          |
|-------------------------------|--------------------------------------------------------------------|
| ExpressVPN                    | `EXPRESSVPN_ACTIVATION_CODE`                                       |
| IPVanish                      | `IPVANISH_USERNAME`, `IPVANISH_PASSWORD`                           |
| Mullvad                       | `MULLVAD_ACCOUNT_NUMBER`                                           |
| NordVPN                       | `NORDVPN_TOKEN`                                                    |
| Private Internet Access (PIA) | `PRIVATEINTERNETACCESS_USERNAME`, `PRIVATEINTERNETACCESS_PASSWORD` |
| Proton VPN (OpenVPN)          | `PROTON_OPENVPN_USERNAME`, `PROTON_OPENVPN_PASSWORD`               |
| Surfshark (OpenVPN)           | `SURFSHARK_OPENVPN_USERNAME`, `SURFSHARK_OPENVPN_PASSWORD`         |
| Surfshark (WireGuard)         | `SURFSHARK_WIREGUARD_PRIVATE_KEYS`, `SURFSHARK_PROTOCOL=wireguard` |

Proton VPN uses the OpenVPN/IKEv2 credentials from your Proton account page,
not your regular Proton account password. Tundler automatically downloads
Proton server metadata during container configuration and generates the
OpenVPN profile at connection time. Optional settings:
`PROTON_OPENVPN_PROTOCOL=udp|tcp` (default `udp`) and `PROTON_OPENVPN_PORT`
(defaults to `1194` for UDP and `443` for TCP). `PROTON_SERVERS_URL` may be
set to override the server metadata source.

IPVanish has no Linux CLI; Tundler downloads IPVanish's official OpenVPN
`configs.zip` during container configuration and connects with the username
and password from your IPVanish account. `IPVANISH_CONFIGS_URL` may be set
to override the configs source.

##### Tundler options

| Variable          | Default | Description                                                        |
|-------------------|---------|--------------------------------------------------------------------|
| `TUNDLER_VPN_DNS` | `false` | Route proxy DNS queries through the VPN tunnel for full privacy    |

### Configuration

When present, `~/.config/tundler/tundler.yaml` is read at startup:

```yaml
debug: true
telemetry: false
plugins:
  - vpnipobserver
providers:
  - nordvpn:
      locations:
        allow:
          - France
          - Germany
        block:
          - United_States
```

- `debug` enables verbose logging and may also be set with `-d/--debug`.
- `telemetry` enables anonymous usage statistics (disabled by default). Collects provider, location, and VPN IP (the IP assigned by the VPN, not your real IP). May also be set with `--telemetry`.
- `plugins` enables specific sidecar plugins. When omitted, every compiled-in plugin is enabled.
- `providers.<name>.locations.allow` restricts the random locations used when `location` is omitted in API calls. When empty, the provider's full location list is used.
- `providers.<name>.locations.block` removes locations from the candidate pool (the `allow` list above, or the provider's full list when `allow` is empty).
- `login` automatically authenticates a comma-separated list of providers at startup (`all` for every provider).

> The previous flat `locations: [France, Germany]` form is no longer accepted; migrate to `locations.allow:`.

## REST API

| Endpoint      | Method | Query params                          | Description                                         |
|---------------|--------|---------------------------------------|-----------------------------------------------------|
| `/`           | GET    | –                                     | List providers and login state                      |
| `/connect`    | POST   | `locations.allow`, `locations.block`, `providers` *(optional)* | Connect to a random location/provider from the allow set, minus the block set |
| `/disconnect` | POST   | –                                     | Tear down the current tunnel                        |
| `/locations`  | GET    | –                                     | List available locations for logged in providers    |
| `/login`      | POST   | `providers` *(optional)*              | Login comma-separated providers or all when omitted |
| `/logout`     | POST   | `providers` *(optional)*              | Logout listed providers, or all if empty            |
| `/plugins`    | GET    | –                                     | List enabled sidecar plugins with `id` and `name`   |
| `/status`     | GET    | –                                     | Return tunnel state, IP and provider in use         |

Compiled plugins are mounted below `/plugins/<id>/...`.

The built-in `vpnipobserver` plugin exposes:

| Endpoint                         | Method | Description                                                   |
|----------------------------------|--------|---------------------------------------------------------------|
| `/plugins/vpnipobserver/ips`     | GET    | List VPN IPs with last-seen timestamp plus provider/region data |

## Extending Tundler

1. Copy `docker/providers/nordvpn` to `docker/providers/<your_provider>`.
2. Implement the `install.sh` and `configure.sh` scripts for your provider.
3. Copy `internal/provider/nordvpn` to `internal/provider/<your_provider>` and implement the interface.
4. Add a blank import in `internal/provider/register/register.go`:

```go
import _ "github.com/laurentpellegrino/tundler/internal/provider/<your_provider>"
```

5. Document new environment variables in this README.

## Injecting Sidecar Plugins

Provider integrations remain the core extension point for tunnel control. If you
need extra features that should not affect that core API, add a plugin instead:

1. Create `internal/plugin/<your_plugin>`.
2. Implement the `internal/plugin`.Plugin interface.
3. Register it in `init()` by adding it to `plugin.Registry`.
4. Add a blank import in `internal/plugin/register/register.go`.

Plugins are isolated in two ways:

- They only receive tunnel lifecycle events after Tundler has already connected or disconnected.
- Their HTTP handlers live under `/plugins/<id>/...`, separate from the main API.

Plugin metadata and events:

- Every plugin must expose a stable `id` and a human-readable `name`.
- Plugins receive `connected` and `disconnected` events.
- Event payloads include `provider`, `location`, `region` when available, `ip`, and `timestamp`.

## Contributing

Pull requests are welcome.
