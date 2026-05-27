#!/usr/bin/env bash
set -e

# Install OpenVPN for IPVanish connections.
# IPVanish has no Linux CLI; we use its official OpenVPN configs.zip.
apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    curl \
    ca-certificates \
    unzip

# Pull configs.zip from the `ipvanish-configs` GitHub release at
# IMAGE-BUILD time. The release asset is refreshed daily by the
# update-ipvanish-configs workflow, which mirrors
# configs.ipvanish.com via Cloudflare WARP (the direct source is
# Cloudflare-bot-blocked from GitHub Actions runner IPs, but the
# GH release CDN is reachable from everywhere — so this curl
# works in both CI and in-cluster rebuilds without needing WARP).
CONFIG_DIR=/etc/ipvanish/openvpn
CONFIGS_URL="${IPVANISH_CONFIGS_URL:-https://github.com/laurentpellegrino/tundler/releases/download/ipvanish-configs/configs.zip}"
TMP_ZIP="$(mktemp)"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

curl -fsSL --max-time 120 "$CONFIGS_URL" -o "$TMP_ZIP"
unzip -oq "$TMP_ZIP" -d "$CONFIG_DIR"
rm -f "$TMP_ZIP"
echo "IPVanish: baked $(find "$CONFIG_DIR" -maxdepth 1 -name 'ipvanish-*.ovpn' | wc -l) server configs into image."
