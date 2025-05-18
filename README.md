# Tundler

Tundler ("tunnel bundler") is a Docker image with a slim REST API (port 4242) for seamless tunnel rotation across 
providers. It also exposes by default an optional VPN-routed HTTP proxy on port 8484.

## Quick Start

See `docker/build.sh` and `docker/run.sh`.

### Environment variables per provider

| Provider   | Accepted variables           |
|------------|------------------------------|
| ExpressVPN | `EXPRESSVPN_ACTIVATION_CODE` |
| NordVPN    | `NORDVPN_TOKEN`              |

---

## REST API

| Endpoint      | Method | Query params                      | Description                                         |
|---------------|--------|-----------------------------------|-----------------------------------------------------|
| `/`           | GET    | –                                 | Lists **providers** supported along with login state |
| `/connect`    | POST   | `location, provider` *(optional)* | Connect to a new location, either random or provided |
| `/disconnect` | POST   | –                                 | Tears down tunnel (idempotent)                      |
| `/login`      | POST   | `provider` *(optional)*           | Logs in one provider, or **all** when omitted       |
| `/logout`     | POST   | `provider` *(optional)*           | Logs out one provider, or **all** when omitted      |
| `/status`     | GET    | –                                 | Returns connection state, IP and provider in use    |

---

## Extending Tundler

1. Copy `docker/providers/nordvpn` → `docker/providers/your_new_vpn_provider`.
2. Edit the scripts `install.sh` and `configure.sh` in `docker/providers/your_new_vpn_provider` that are used respectively to install your provider client CLI, and setup it before first usage.
3. Copy `internal/provider/nordvpn` → `internal/provider/your_new_vpn_provider`.
4. Implement the interface methods to wrap your CLI.
5. Add a blank import in `internal/provider/register/register.go`:

```go
import _ "github.com/laurentpellegrino/tundler/internal/provider/your_new_vpn_provider"
```

6. Document the environment variables for your new VPN provider in this README.

Pull requests are welcome.