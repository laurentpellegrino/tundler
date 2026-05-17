#!/usr/bin/env bash
set -e

CONFIG_DIR="${IPVANISH_CONFIG_DIR:-/etc/ipvanish/openvpn}"
CONFIGS_URL="${IPVANISH_CONFIGS_URL:-https://configs.ipvanish.com/configs/configs.zip}"
TMP_ZIP="$(mktemp)"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

echo "Downloading IPVanish OpenVPN configurations..."
curl -fsSL --max-time 120 "$CONFIGS_URL" -o "$TMP_ZIP"

echo "Extracting IPVanish OpenVPN configurations..."
unzip -oq "$TMP_ZIP" -d "$CONFIG_DIR"
rm -f "$TMP_ZIP"

echo "IPVanish configuration completed ($(find "$CONFIG_DIR" -maxdepth 1 -name 'ipvanish-*.ovpn' | wc -l) servers)."
