#!/usr/bin/env bash
set -e

# Norton VPN runs as OpenVPN-direct (no provider daemon) — the Go binary spawns
# openvpn at connect time, authenticating with the per-device
# NORTON_USERNAME/NORTON_PASSWORD and the CA embedded in the binary.
apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    ca-certificates \
    curl \
    python3
echo "norton: openvpn installed ($(openvpn --version 2>&1 | head -1))"

# Refreshable exit catalog: the `norton-servers` release asset (built from the
# SurfEasy discovery API by the update-norton-servers workflow / cmd/norton-updater),
# baked to /etc/norton/servers.json. Soft-fail: if the release is unreachable at
# build time, the binary falls back to its embedded snapshot at runtime.
SERVERS_URL="${NORTON_SERVERS_URL:-https://github.com/laurentpellegrino/tundler/releases/download/norton-servers/servers.json}"
mkdir -p /etc/norton
if curl -fsSL --max-time 60 "$SERVERS_URL" -o /etc/norton/servers.json; then
    n=$(python3 -c "import json; print(len(json.load(open('/etc/norton/servers.json'))))" 2>/dev/null || echo "?")
    echo "norton: fetched $n exit servers from $SERVERS_URL"
else
    echo "norton: WARN — could not fetch $SERVERS_URL; using the embedded fallback at runtime"
    rm -f /etc/norton/servers.json
fi
