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

# configs.zip is committed to the repo at
# docker/providers/ipvanish/configs.zip and refreshed daily by the
# update-ipvanish-configs GitHub Actions workflow (which fetches it
# from configs.ipvanish.com via Cloudflare WARP — works around the
# Cloudflare bot-block that 403s GitHub Actions runner IPs on the
# direct path). Nothing to download at image build time.
CONFIG_DIR=/etc/ipvanish/openvpn
CONFIGS_ZIP=/opt/providers/ipvanish/configs.zip

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

unzip -oq "$CONFIGS_ZIP" -d "$CONFIG_DIR"
echo "IPVanish: baked $(find "$CONFIG_DIR" -maxdepth 1 -name 'ipvanish-*.ovpn' | wc -l) server configs into image."
