#!/usr/bin/env bash
set -e

# Mullvad runs over WireGuard directly via wg-quick using pre-generated
# per-pod keys (see internal/provider/mullvad/mullvad.go) — no Mullvad
# daemon/CLI. Install only the standard WireGuard userspace tools, same as
# the surfshark WireGuard path.
apt-get update
apt-get install -y --no-install-recommends \
    wireguard-tools \
    curl \
    ca-certificates

# Bake the WireGuard relay list into the image at build time so the runtime
# provider has no per-pod dependency on Mullvad's API (it reads
# /etc/mullvad/relays.json). The list is NOT versioned in the repo.
#
# Primary source: the `mullvad-relays` GitHub release asset, refreshed
# daily by .github/workflows/update-mullvad-relays.yml (trimmed JSON).
# Fallback: Mullvad's PUBLIC relay API directly — unlike cyberghost there
# is no embedded copy, so the build must always end with a valid file;
# the public API makes a live fetch a safe bootstrap (and survives a
# missing/empty release on first build). The provider only reads the
# fields it needs, so the untrimmed API response parses fine too.
RELEASE_URL="${MULLVAD_RELAYS_URL:-https://github.com/laurentpellegrino/tundler/releases/download/mullvad-relays/relays.json}"
API_URL="https://api.mullvad.net/app/v1/relays"
mkdir -p /etc/mullvad
if curl -fsSL --max-time 60 "$RELEASE_URL" -o /etc/mullvad/relays.json; then
    echo "Mullvad: baked relay list from release $RELEASE_URL"
elif curl -fsSL --max-time 60 "$API_URL" -o /etc/mullvad/relays.json; then
    echo "Mullvad: release unavailable; baked LIVE relay list from $API_URL"
else
    echo "Mullvad: ERROR — could not obtain relay list from release or API" >&2
    exit 1
fi

# Sanity: the file must actually contain WireGuard relay entries, else the
# provider has nothing to connect to. Cheap grep (no python/jq dependency).
if ! grep -q '"public_key"' /etc/mullvad/relays.json; then
    echo "Mullvad: ERROR — relay list has no WireGuard relays" >&2
    exit 1
fi
echo "Mullvad: relay list baked ($(wc -c < /etc/mullvad/relays.json) bytes)"
