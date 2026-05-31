#!/usr/bin/env bash
set -e

# IPVanish OpenVPN configs are now baked into the image at BUILD time
# (see install.sh). At runtime we only verify they're present — a missing
# directory would mean a broken image, not a recoverable runtime state.
CONFIG_DIR="${IPVANISH_CONFIG_DIR:-/etc/ipvanish/openvpn}"

COUNT=$(find "$CONFIG_DIR" -maxdepth 1 -name 'ipvanish-*.ovpn' 2>/dev/null | wc -l)
if [[ "$COUNT" -eq 0 ]]; then
    echo "ERROR: no IPVanish OpenVPN configs found in $CONFIG_DIR — broken image" >&2
    exit 1
fi
echo "IPVanish: $COUNT server configs available (baked at build time)."
