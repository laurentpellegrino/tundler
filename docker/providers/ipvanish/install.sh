#!/usr/bin/env bash
set -e

# Install OpenVPN for IPVanish connections.
# IPVanish has no Linux CLI; we use its official OpenVPN configs.zip.
apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    curl \
    ca-certificates \
    gpg \
    unzip

# IPVanish drops datacenter source IPs at L3, so from the fleet the
# OpenVPN connection rides Cloudflare WARP in proxy mode (TCP/443
# through WARP's local SOCKS5 proxy, which presents a Cloudflare source
# IP). Install the WARP client here so the provider can bring the proxy
# up at runtime — see internal/shared/warpproxy and the package doc in
# internal/provider/ipvanish/ipvanish.go.
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
  | gpg --yes --dearmor \
      --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ jammy main" \
  > /etc/apt/sources.list.d/cloudflare-client.list
apt-get update
apt-get install -y --no-install-recommends cloudflare-warp
echo "IPVanish: WARP transport installed ($(warp-cli --version 2>&1 | head -1))"

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
