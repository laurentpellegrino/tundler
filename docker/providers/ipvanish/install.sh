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

# Download IPVanish OpenVPN configs at BUILD time. configs.ipvanish.com sits
# behind Cloudflare and 403s requests from many cloud/datacenter egress IPs
# (verified May 2026 from a k8s production cluster). Building this into the
# image keeps the runtime configure.sh idempotent and offline-safe — pods
# don't need to fetch from a CDN that may block them.
CONFIG_DIR=/etc/ipvanish/openvpn
CONFIGS_URL="${IPVANISH_CONFIGS_URL:-https://configs.ipvanish.com/configs/configs.zip}"
TMP_ZIP="$(mktemp)"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

echo "Downloading IPVanish OpenVPN configurations at build time..."
curl -fsSL --max-time 120 "$CONFIGS_URL" -o "$TMP_ZIP"
unzip -oq "$TMP_ZIP" -d "$CONFIG_DIR"
rm -f "$TMP_ZIP"
echo "IPVanish: baked $(find "$CONFIG_DIR" -maxdepth 1 -name 'ipvanish-*.ovpn' | wc -l) server configs into image."
