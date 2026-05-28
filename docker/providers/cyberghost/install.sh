#!/usr/bin/env bash
set -e

# CyberGhost runs as OpenVPN-direct (no provider daemon) — same
# pattern as protonvpn / surfshark. The Go binary spawns openvpn at
# connect time and reads the per-pod cert/key/user/pass from
# POD_<n>_* env vars (populated by the StatefulSet's envFrom of
# vpn-credentials-cyberghost).
#
# We do NOT bake server configs into the image at build time. The
# server list ships embedded inside the tundler-tunnel binary via
# go:embed (internal/provider/cyberghost/servers.json), refreshed
# daily by .github/workflows/update-cyberghost-servers.yml. The
# .ovpn config itself is generated at connect time from a template
# in cyberghost.go.

apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    ca-certificates \
    curl
echo "CyberGhost: openvpn installed ($(openvpn --version 2>&1 | head -1))"

# Download the daily-refreshed server list from the `cyberghost-servers`
# GitHub release tag, baked into the image at build time. The
# runtime binary prefers this file over its embedded fallback (see
# loadServers() in internal/provider/cyberghost/cyberghost.go).
#
# Refreshed daily by .github/workflows/update-cyberghost-servers.yml,
# which DNS-resolves every {groupID}-{cc}.cg-dialup.net candidate
# (no CyberGhost API auth required — gluetun does the same).
#
# Soft-fail: if the release is unreachable at build time (e.g. fresh
# repo with no first release yet, or network blip), keep going —
# the embedded servers.json kicks in at runtime.
SERVERS_URL="${CYBERGHOST_SERVERS_URL:-https://github.com/laurentpellegrino/tundler/releases/download/cyberghost-servers/servers.json}"
mkdir -p /etc/cyberghost
if curl -fsSL --max-time 60 "$SERVERS_URL" -o /etc/cyberghost/servers.json; then
    n=$(python3 -c "import json; print(len(json.load(open('/etc/cyberghost/servers.json'))))" 2>/dev/null || echo "?")
    echo "CyberGhost: baked $n servers from $SERVERS_URL into image"
else
    echo "CyberGhost: WARN — could not fetch $SERVERS_URL; binary will use its embedded fallback servers.json at runtime"
fi
