# HMA native provider

HMA account authentication and device provisioning follow the official macOS
client. The tunnel uses OpenVPN endpoints and device credentials returned by
the same native API. No profile archive or account secret is baked into images.

## Configuration

Use tundler account fields `username` (HMA account email) and `password`.
For local development, use the already authenticated Bao CLI:

```sh
export BAO_ADDR=https://bao.elaunira.com
export BAO_NAMESPACE=ipregistry/production
export TUNDLER_ACCOUNT_USERNAME="$(bao kv get -field=username kv/vpn/hidemyass)"
export TUNDLER_ACCOUNT_PASSWORD="$(bao kv get -field=password kv/vpn/hidemyass)"
```

Keep shell tracing disabled when loading secrets. The legacy
`HIDEMYASS_USERNAME` / `HIDEMYASS_PASSWORD` variables also work.

The image installs `openvpn`, `iproute2`, `iptables`, `curl` and CA certificates.
Connections require Linux, `/dev/net/tun`, and `NET_ADMIN` in the provider's
isolated container or network namespace. The Go provider owns the OpenVPN child;
there is no separately managed vendor daemon.

- `HIDEMYASS_STATE_DIR`: private device/session directory, default
  `/var/lib/tundler/hidemyass`. Persist it across container restarts to reuse
  valid tokens and credentials. State files are written atomically with mode
  `0600`; directories are created with mode `0700`. An existing state directory
  must already be private (mode `0700`).
- `HIDEMYASS_DEVICE_ID`: optional explicit stable fingerprint. Otherwise the
  provider derives one from the account email and `POD_NAME` (hostname locally).
  Give different pods different fingerprints and retain a pod's fingerprint
  across restarts. Set account slot capacity to the subscription's device limit.

`Login` obtains a device session, its transport credentials and a live country
catalog. Reauthentication keeps the same fingerprint and reuses credentials for
that device. An expired or rejected access token triggers native authentication
again. An explicit OpenVPN device-authentication rejection refreshes the device
credentials once; transport failures do not rotate credentials. `Connect` selects a live UDP OpenVPN endpoint in the requested country or
city. Country names use tundler's geo vocabulary; the requested location
round-trips through `ActiveLocation`.

## Transport and proxy protection

OpenVPN receives the device username and password over a Unix management socket
inside a fresh private directory. Generated configuration files contain public
CA certificates, not account or device passwords. The child inherits only
`PATH` and `LANG`. Its output and management messages are never logged.

TLS checks require the API-supplied CA chain, server certificate usage and the
exact certificate name `openvpn.gen-vpn.com`. Expired CA entries are excluded;
the current API bundle includes a retired root alongside its replacement. A
bundle without a currently valid CA fails. TLS versions below 1.2 are rejected.

The management interface reports connection state and the negotiated IPv4
address. The proxy rejects dials while disconnected or reconnecting and binds
all TCP connections to that address. A source-specific firewall rule rejects
packets leaving through any interface other than `tundler-hma`. Rotation closes
existing proxy sockets before stopping the owned OpenVPN process. Cleanup never
kills unrelated VPN processes. Public-IP status probes use the proxy dialer.

`Logout` removes the cached device session but leaves an established connection
running, as required by the provider interface. `Disconnect` closes the proxy
sockets, stops the child and removes its firewall rule. A failed cleanup stays
pending so a later disconnect can retry it. OpenVPN is held on management loss;
the supervisor also terminates it if its management connection fails. On Linux,
a parent-death signal terminates the child if the runtime crashes.

## Protocol reference

Account/API reference: official HMA macOS **26.8.0**, retrieved from
[the official Mac download](https://www.hidemyass.com/download-thank-you.php?product=HMA-MAC).
OpenVPN discovery, device authentication and certificate checks were verified
against the live service. The macOS client's IKEv2 transport is not used here.

1. POST `https://my-mac.avast.com/v1/command/login/email` with account email,
   password and `requestedTicketTypes: ["DEVT", "LICT"]`. Use the native request
   digest, product ID `79` and `Vaar-Version: 0`; require HTTP 200 and
   `Vaar-Status: 0`.
2. POST `/v1/query/get-all-user-licenses`, authenticated with the **DEVT** ticket.
   Select an unexpired `HideMyAss` subscription with an ID and wallet key.
   Expiration timestamps are milliseconds since the epoch.
3. POST `https://api.se-platform.com/aladdin/v1/authorization/associate-license`
   with `wallet_key`, `container_id` (subscription ID), stable
   `device_fingerprint` and `client_package_name: "com.hidemyass.osx"`.
   The response supplies `device_udid`, `access_token` and `refresh_token`.
4. PUT `/passage/v6/devices/{device_udid}/credentials` with bearer authorization.
   Use `device_udid`, `device_password` and `openvpn_ca_certificate`. The same
   response also contains an IKEv2 identity; that identity is not required by
   this transport. Provision only when no cached device credentials exist or once following an
   explicit device-authentication rejection.
5. GET `/discovery/v12/geos` for country/city location keys and active states.
6. GET `/discovery/v9/discover?protocol=OPENVPN&location_key=...` for live server
   addresses and UDP ports. Catalog and discovery versions are independent.

The request identity uses client type `hma201`, platform `mac-x86-64`, client
name `com.privax.osx.provpn` and the HMA tenant. Aladdin uses SDK `mac-1.0.0`;
other VPN APIs use `7.0.0`. Require status code `0` in wrapped responses. Fixed
application signing/API identities are shared constants from the public app;
account passwords, license keys, tokens and response/debug bodies remain private.

The obsolete 5.4.22 bootstrap/SLC backend and CAPTCHA-based website login are
not part of this flow. OpenVPN management follows its
[documented Unix socket protocol](https://openvpn.net/community-docs/management-interface/).

## Image publishing

The existing [image workflow](../../../.github/workflows/docker-image.yml)
already includes `hidemyass` in its provider matrix. A push to `main` runs the
full Go test/vet checks and builds [the shared tunnel image](../../../docker/Dockerfile.tunnel)
with `PROVIDER=hidemyass`, then publishes both tags:

- `ghcr.io/laurentpellegrino/tundler-hidemyass:latest`
- `ghcr.io/laurentpellegrino/tundler-hidemyass:<full-commit-SHA>`

The same workflow supports manual runs and scheduled rebuilds. Builds require
no HMA account credentials or OpenBao access; supply account credentials only
at runtime through tundler's account configuration.

## Validation

```sh
go test -race ./internal/provider/hidemyass
go vet ./internal/provider/hidemyass
go build -tags provider_hidemyass ./cmd/tundler-tunnel
```

Live tests require account credentials in the environment and explicit opt-in:

- `HIDEMYASS_LIVE_TEST=1`: `TestLiveAccount` checks authentication/subscriptions
  without provisioning a device.
- `HIDEMYASS_LIVE_CONTROL_TEST=1`: `TestLiveOpenVPNControl` checks native login,
  device credentials, exact server certificate verification, management socket
  authentication, virtual-IP negotiation and process cleanup. Its null device
  leaves host interfaces/routes untouched and does **not** prove forwarding.
- `HIDEMYASS_LIVE_TUNNEL_TEST=1`: `TestLiveTunnel` connects the real TUN interface,
  verifies a changed proxy exit IP and checks disconnection. Run only in an
  isolated container/network namespace with TUN and `NET_ADMIN`.

Both device tests require an explicit `HIDEMYASS_DEVICE_ID`. They reuse that
fingerprint and never print account credentials or device tokens. An isolated firewall test also verified that the egress rule blocks fallback
through the host interface and that removing the rule restores connectivity.
Full traffic validation requires a host providing `/dev/net/tun`; the current development
host does not expose that device or permit creating it in a rootless container.
