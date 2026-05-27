#!/usr/bin/env bash
set -e

# Install OpenVPN for ProtonVPN connections.
# ProtonVPN has no official Linux CLI; we drive the open-source
# openvpn client with credentials handed via auth-user-pass.
apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    curl \
    ca-certificates

# Pull servers.json from the `protonvpn-servers` GitHub release at
# IMAGE-BUILD time. The release asset is refreshed daily by the
# update-proton-servers workflow which SRP-authenticates against
# api.proton.me via Cloudflare WARP and uploads the rendered
# logical-server catalog. The tunnel-side provider lazy-loads this
# file at startup (see internal/provider/protonvpn/protonvpn.go).
SERVERS_FILE="${PROTON_SERVERS_FILE:-/etc/protonvpn/servers.json}"
SERVERS_URL="${PROTON_SERVERS_URL:-https://github.com/laurentpellegrino/tundler/releases/download/protonvpn-servers/servers.json}"

mkdir -p "$(dirname "$SERVERS_FILE")"
curl -fsSL --max-time 60 "$SERVERS_URL" -o "$SERVERS_FILE"
# Don't require a JSON parser in the image just to print a count;
# the file's existence + non-zero size is enough of a sanity check
# at build time.
SIZE=$(stat -c%s "$SERVERS_FILE")
if [[ "$SIZE" -lt 100 ]]; then
    echo "ERROR: ProtonVPN servers.json from $SERVERS_URL is suspiciously small ($SIZE bytes)" >&2
    exit 1
fi
echo "ProtonVPN: baked $SIZE-byte servers.json from $SERVERS_URL into image."
