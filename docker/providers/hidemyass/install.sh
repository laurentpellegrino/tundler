#!/usr/bin/env bash
set -e

# Install OpenVPN for HMA (HideMyAss!) connections.
# HMA discontinued its Linux client in 2023 and never had a headless
# CLI; we drive openvpn against its per-location .ovpn profiles.
apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    curl \
    ca-certificates \
    unzip

# Bake the profiles from the `hidemyass-configs` GitHub release at
# IMAGE-BUILD time. Unlike ipvanish/cyberghost there is no upstream
# to mirror daily: HMA's public config host (vpn.hidemyass.com/
# vpn-config/) no longer resolves, so the account holder publishes
# the bundle obtained from the HMA dashboard / support as
# configs.zip on that release:
#
#   gh release create hidemyass-configs --title "HMA OpenVPN configs" --notes "" \
#   gh release upload hidemyass-configs configs.zip --clobber
#
# Both layouts HMA has shipped are accepted (flat
# Country.City.UDP.ovpn files, or UDP/ + TCP/ directories); the Go
# loader walks the directory recursively.
#
# Soft-fail: a missing release must not break the whole provider
# matrix in CI — the image still builds, configure.sh flags the
# empty directory loudly at boot and Login() fails with a clear
# "no HMA OpenVPN profiles found" error.
CONFIG_DIR=/etc/hidemyass/openvpn
CONFIGS_URL="${HIDEMYASS_CONFIGS_URL:-https://github.com/laurentpellegrino/tundler/releases/download/hidemyass-configs/configs.zip}"
TMP_ZIP="$(mktemp)"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

if curl -fsSL --max-time 120 "$CONFIGS_URL" -o "$TMP_ZIP" && unzip -tq "$TMP_ZIP" >/dev/null 2>&1; then
    unzip -oq "$TMP_ZIP" -d "$CONFIG_DIR"
    echo "HideMyAss: baked $(find "$CONFIG_DIR" -name '*.ovpn' | wc -l) OpenVPN profiles into image."
else
    echo "HideMyAss: WARN — could not fetch a valid configs.zip from $CONFIGS_URL; image has NO profiles (publish the hidemyass-configs release asset and rebuild)."
fi
rm -f "$TMP_ZIP"
