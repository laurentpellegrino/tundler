#!/usr/bin/env bash
set -e

# OVPN.com runs as OpenVPN-direct (no provider daemon) — the Go binary
# spawns openvpn at connect time, authenticating with the shared
# OVPN_USERNAME/OVPN_PASSWORD and the CA + tls-auth embedded in the binary.
apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    ca-certificates \
    curl
echo "OVPN: openvpn installed ($(openvpn --version 2>&1 | head -1))"

# Bake the datacenter list into the image at build time so the runtime
# provider has no per-pod dependency on OVPN's API (it reads
# /etc/ovpn/servers.json). NOT versioned in the repo.
#
# Primary: the `ovpn-servers` GitHub release asset, refreshed daily by
# .github/workflows/update-ovpn-servers.yml. Fallback: OVPN's PUBLIC
# datacenters API directly — there is no embedded copy, so the build must
# always end with a valid file; the public API makes a live fetch a safe
# bootstrap (and survives a missing release on first build).
RELEASE_URL="${OVPN_SERVERS_URL:-https://github.com/laurentpellegrino/tundler/releases/download/ovpn-servers/servers.json}"
API_URL="https://www.ovpn.com/v1/api/client/datacenters"
mkdir -p /etc/ovpn
if curl -fsSL --max-time 60 "$RELEASE_URL" -o /etc/ovpn/servers.json; then
    echo "OVPN: baked datacenter list from release $RELEASE_URL"
elif curl -fsSL --max-time 60 "$API_URL" -o /etc/ovpn/servers.json; then
    echo "OVPN: release unavailable; baked LIVE datacenter list from $API_URL"
else
    echo "OVPN: ERROR — could not obtain datacenter list from release or API" >&2
    exit 1
fi

# Sanity: must contain datacenter slugs, else there's nothing to connect to.
if ! grep -q '"slug"' /etc/ovpn/servers.json; then
    echo "OVPN: ERROR — datacenter list has no servers" >&2
    exit 1
fi
echo "OVPN: datacenter list baked ($(wc -c < /etc/ovpn/servers.json) bytes)"
