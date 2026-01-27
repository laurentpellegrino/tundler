# Tundler

Tundler ("tunnel bundler") packages a small REST API in a Docker image to manage multiple VPN providers.
It can rotate tunnels on demand and exposes an HTTP proxy routed through the active VPN.

Unlike other solutions, it depends as much as possible on the VPN providers’ official client libraries
to minimise breakage and remains stateless on its own.

## Features

- REST API on port `4242` for controlling VPN connections.
- ExpressVPN, Mullvad, NordVPN, Private Internet Access (PIA) and Surfshark support out of the box.
- Optional HTTP proxy on port `8484` with Envoy-based HTTP/HTTPS support.
- YAML configuration file for location filtering and debug mode.
- Easily extensible to add new providers.

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
    │   │  ┌─────────────┐      ┌─────────────────┐                  │   │
    │   │  │ Tundler API │      │   Envoy Proxy   │                  │   │
    │   │  │    :4242    │      │     :8484       │                  │   │
    │   │  └─────────────┘      └─────────────────┘                  │   │
    │   │                                │                           │   │
    │   │                                │ fwmark 200                │   │
    │   │                                │ (policy routing)          │   │
    │   │                                ▼                           │   │
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
    │   │        │              vpn-ns                 │             │   │
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
MULLVAD_ACCOUNT_NUMBER=<account> \
NORDVPN_TOKEN=<token> \
PRIVATEINTERNETACCESS_USERNAME=<username> \
PRIVATEINTERNETACCESS_PASSWORD=<password> \
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

| Provider                      | Variables                                                          |
|-------------------------------|--------------------------------------------------------------------|
| ExpressVPN                    | `EXPRESSVPN_ACTIVATION_CODE`                                       |
| Mullvad                       | `MULLVAD_ACCOUNT_NUMBER`                                           |
| NordVPN                       | `NORDVPN_TOKEN`                                                    |
| Private Internet Access (PIA) | `PRIVATEINTERNETACCESS_USERNAME`, `PRIVATEINTERNETACCESS_PASSWORD` |
| Surfshark (OpenVPN)           | `SURFSHARK_OPENVPN_USERNAME`, `SURFSHARK_OPENVPN_PASSWORD`         |
| Surfshark (WireGuard)         | `SURFSHARK_WIREGUARD_PRIVATE_KEYS`, `SURFSHARK_PROTOCOL=wireguard` |

### Configuration

When present, `~/.config/tundler/tundler.yaml` is read at startup:

```yaml
debug: true
telemetry: false
providers:
  - nordvpn:
      locations:
        - France
        - Germany
```

- `debug` enables verbose logging and may also be set with `-d/--debug`.
- `telemetry` enables anonymous usage statistics (disabled by default). Collects provider, location, and VPN IP (the IP assigned by the VPN, not your real IP). May also be set with `--telemetry`.
- `providers.<name>.locations` restricts the random locations used when `location` is omitted in API calls.
- `login` automatically authenticates a comma-separated list of providers at startup (`all` for every provider).

## REST API

| Endpoint      | Method | Query params                        | Description                                         |
|---------------|--------|-------------------------------------|-----------------------------------------------------|
| `/`           | GET    | –                                   | List providers and login state                      |
| `/connect`    | POST   | `locations`, `providers` *(optional)* | Connect to a random location/provider from the list |
| `/disconnect` | POST   | –                                   | Tear down the current tunnel                        |
| `/login`      | POST   | `providers` *(optional)*            | Login comma-separated providers or all when omitted |
| `/logout`     | POST   | `providers` *(optional)*            | Logout listed providers, or all if empty            |
| `/status`     | GET    | –                                   | Return tunnel state, IP and provider in use         |

## Extending Tundler

1. Copy `docker/providers/nordvpn` to `docker/providers/<your_provider>`.
2. Implement the `install.sh` and `configure.sh` scripts for your provider.
3. Copy `internal/provider/nordvpn` to `internal/provider/<your_provider>` and implement the interface.
4. Add a blank import in `internal/provider/register/register.go`:

```go
import _ "github.com/laurentpellegrino/tundler/internal/provider/<your_provider>"
```

5. Document new environment variables in this README.

## Contributing

Pull requests are welcome.
