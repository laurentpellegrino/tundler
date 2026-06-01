#!/usr/bin/env bash
set -e

# PureVPN runs as OpenVPN-direct (no provider daemon) — the Go binary spawns
# openvpn at connect time, authenticating with the shared
# PUREVPN_USERNAME/PUREVPN_PASSWORD and the CA + tls-auth embedded in the
# binary.
apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    ca-certificates \
    curl \
    unzip
echo "PureVPN: openvpn installed ($(openvpn --version 2>&1 | head -1))"

# Bake the server-slug list into the image at build time so the runtime
# provider has no per-pod dependency on PureVPN's CDN (it reads
# /etc/purevpn/servers.json — a JSON array of slugs like "de2","uswdc2").
# NOT versioned in the repo.
#
# Primary: the `purevpn-servers` GitHub release asset, refreshed daily by
# .github/workflows/update-purevpn-servers.yml. Fallback: PureVPN's PUBLIC
# OpenVPN config bundle (no login) — there is no embedded copy, so the build
# must always end with a valid file; extracting the UDP config filenames
# gives the slug list.
RELEASE_URL="${PUREVPN_SERVERS_URL:-https://github.com/laurentpellegrino/tundler/releases/download/purevpn-servers/servers.json}"
BUNDLE_URL="https://d11a57lttb2ffq.cloudfront.net/heartbleed/router/Recommended-CA2.zip"
mkdir -p /etc/purevpn
if curl -fsSL --max-time 60 "$RELEASE_URL" -o /etc/purevpn/servers.json; then
    echo "PureVPN: baked server list from release $RELEASE_URL"
else
    echo "PureVPN: release unavailable; extracting slug list from $BUNDLE_URL"
    tmp="$(mktemp -d)"
    curl -fsSL --max-time 90 "$BUNDLE_URL" -o "$tmp/pv.zip"
    unzip -o -q "$tmp/pv.zip" -d "$tmp"
    # One slug per UDP config: <slug>-auto-udp-qr.ovpn -> "slug".
    find "$tmp" -name '*-auto-udp-qr.ovpn' -printf '%f\n' \
        | sed 's/-auto-udp-qr.ovpn//' \
        | sort -u \
        | sed 's/.*/"&"/' | paste -sd, - | sed 's/^/[/;s/$/]/' \
        > /etc/purevpn/servers.json
    rm -rf "$tmp"
fi

# Sanity: must be a non-trivial JSON array.
n=$(grep -o '"' /etc/purevpn/servers.json | wc -l)
if [ "$n" -lt 20 ]; then
    echo "PureVPN: ERROR — server list looks empty ($n quotes)" >&2
    exit 1
fi
echo "PureVPN: server list baked ($(wc -c < /etc/purevpn/servers.json) bytes)"
