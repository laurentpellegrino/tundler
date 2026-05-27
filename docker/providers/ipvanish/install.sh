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

# Download IPVanish OpenVPN configs at BUILD time. configs.ipvanish.com
# sits behind Cloudflare and 403s requests from many cloud/datacenter
# egress IPs (verified May 2026 from a k8s production cluster AND from
# GitHub Actions runners — same Cloudflare bot-block list). We mirror
# configs.zip as a release asset on this repo: GitHub's release CDN
# isn't on that block list, so the download works from both GitHub
# Actions and from in-cluster rebuilds. To refresh, from a residential
# IP:
#   curl -sLo configs.zip https://configs.ipvanish.com/configs/configs.zip
#   gh release upload ipvanish-configs configs.zip --clobber --repo laurentpellegrino/tundler
# (the trailing /configs/ path matters — the bare /configs.zip URL
# IPVanish previously served at the root now 404s).
CONFIG_DIR=/etc/ipvanish/openvpn
CONFIGS_URL="${IPVANISH_CONFIGS_URL:-https://github.com/laurentpellegrino/tundler/releases/download/ipvanish-configs/configs.zip}"
TMP_ZIP="$(mktemp)"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

echo "Downloading IPVanish OpenVPN configurations at build time..."
curl -fsSL --max-time 120 "$CONFIGS_URL" -o "$TMP_ZIP"
unzip -oq "$TMP_ZIP" -d "$CONFIG_DIR"
rm -f "$TMP_ZIP"
echo "IPVanish: baked $(find "$CONFIG_DIR" -maxdepth 1 -name 'ipvanish-*.ovpn' | wc -l) server configs into image."
