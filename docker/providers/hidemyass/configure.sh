#!/usr/bin/env bash
set -e

# HMA OpenVPN profiles are baked into the image at BUILD time (see
# install.sh). At runtime we only verify they're present — an empty
# directory means the hidemyass-configs release asset was missing
# when the image was built, not a recoverable runtime state.
CONFIG_DIR="${HIDEMYASS_CONFIG_DIR:-/etc/hidemyass/openvpn}"

COUNT=$(find "$CONFIG_DIR" -name '*.ovpn' 2>/dev/null | wc -l)
if [[ "$COUNT" -eq 0 ]]; then
    echo "ERROR: no HMA OpenVPN profiles found in $CONFIG_DIR — publish configs.zip on the hidemyass-configs GitHub release and rebuild the image" >&2
    exit 1
fi
echo "HideMyAss: $COUNT OpenVPN profiles available (baked at build time)."
