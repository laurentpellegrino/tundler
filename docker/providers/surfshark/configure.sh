#!/usr/bin/env bash
set -e

# Create directories for Surfshark configs
mkdir -p /etc/surfshark/openvpn
mkdir -p /etc/surfshark/wireguard

# Download OpenVPN configs from Surfshark public API
CONFIG_URL="https://api.surfshark.com/v1/server/configurations"
TMP_ZIP="/tmp/surfshark-configs.zip"
TMP_OVPN="/tmp/sample.ovpn"

echo "Downloading Surfshark OpenVPN configurations..."
curl -sL "$CONFIG_URL" -o "$TMP_ZIP"

# Extract a sample .ovpn file to get CA and TLS-Auth key
unzip -p "$TMP_ZIP" "$(unzip -l "$TMP_ZIP" | grep '\.ovpn$' | head -1 | awk '{print $4}')" > "$TMP_OVPN"

# Extract CA certificate
echo "Extracting CA certificate..."
sed -n '/<ca>/,/<\/ca>/p' "$TMP_OVPN" | sed '1d;$d' > /etc/surfshark/ca.crt

# Extract TLS-Auth key
echo "Extracting TLS-Auth key..."
sed -n '/<tls-auth>/,/<\/tls-auth>/p' "$TMP_OVPN" | sed '1d;$d' > /etc/surfshark/ta.key

# Cleanup
rm -f "$TMP_ZIP" "$TMP_OVPN"

echo "Surfshark certificates configured successfully."
