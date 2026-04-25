#!/usr/bin/env bash
set -e

CONFIG_DIR="/etc/protonvpn/openvpn"
SERVERS_FILE="${PROTON_SERVERS_FILE:-/etc/protonvpn/servers.json}"
SERVERS_URL="${PROTON_SERVERS_URL:-https://raw.githubusercontent.com/qdm12/gluetun/master/internal/storage/servers.json}"

mkdir -p "$CONFIG_DIR" "$(dirname "$SERVERS_FILE")"
chmod 700 "$CONFIG_DIR"

echo "Downloading ProtonVPN OpenVPN server metadata..."
curl -fsSL "$SERVERS_URL" -o "$SERVERS_FILE"

echo "ProtonVPN metadata configured successfully."
