# Tundler

Tundler ("tunnel bundler") packages a small REST API in a Docker image to manage multiple VPN providers.
It can rotate tunnels on demand and optionally expose an HTTP proxy routed through the active VPN.

Unlike other solutions, it depends as much as possible on the VPN providers’ official client libraries 
to minimise breakage and remains stateless on its own.

## Features

- REST API on port `4242` for controlling VPN connections.
- ExpressVPN, Mullvad, NordVPN and Private Internet Access (PIA) support out of the box.
- Optional HTTP proxy on port `8484`.
- YAML configuration file for location filtering and debug mode.
- Easily extensible to add new providers.

## Getting Started

### Build the image

```bash
docker/build.sh
```

### Run the container

```bash
EXPRESSVPN_ACTIVATION_CODE=<code> \
MULLVAD_ACCOUNT_NUMBER=<account> \
NORDVPN_TOKEN=<token> \
PRIVATEINTERNETACCESS_USERNAME=<username> \
PRIVATEINTERNETACCESS_PASSWORD=<password> \
docker/run.sh
```

The API will be reachable on port `4242` and the HTTP proxy on `8484`.

By default, the VPN and HTTP proxy run inside their own network namespace.
The `TUNDLER_NETNS` environment variable specifies the namespace name
(defaults to `vpnns`). VPN daemons are launched in that namespace using
systemd overrides, while the REST API stays in the main namespace so it
remains reachable even when the VPN changes routing.

#### Environment variables

| Provider                      | Variables                                                          |
|-------------------------------|--------------------------------------------------------------------|
| ExpressVPN                    | `EXPRESSVPN_ACTIVATION_CODE`                                       |
| Mullvad                       | `MULLVAD_ACCOUNT_NUMBER`                                           |
| NordVPN                       | `NORDVPN_TOKEN`                                                    |
| Private Internet Access (PIA) | `PRIVATEINTERNETACCESS_USERNAME`, `PRIVATEINTERNETACCESS_PASSWORD` |

### Configuration

When present, `~/.config/tundler/tundler.yaml` is read at startup:

```yaml
debug: true
providers:
  - nordvpn:
      locations:
        - France
        - Germany
```

- `debug` enables verbose logging and may also be set with `-d/--debug`.
- `providers.<name>.locations` restricts the random locations used when `location` is omitted in API calls.
- `login` automatically authenticates a comma-separated list of providers at startup (`all` for every provider).

## REST API

| Endpoint      | Method | Query params                        | Description                                         |
|---------------|--------|-------------------------------------|-----------------------------------------------------|
| `/`           | GET    | –                                   | List providers and login state                      |
| `/connect`    | POST   | `location`, `provider` *(optional)* | Connect to a new location or provider               |
| `/disconnect` | POST   | –                                   | Tear down the current tunnel                        |
| `/login`      | POST   | `providers` *(optional)*            | Login comma-separated providers or all when omitted |
| `/logout`     | POST   | `provider` *(optional)*             | Logout one provider or all when omitted             |
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
