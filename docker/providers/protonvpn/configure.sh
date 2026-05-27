#!/usr/bin/env bash
#
# ProtonVPN server metadata is embedded in the tundler-tunnel binary
# at build time (via go:embed of internal/provider/protonvpn/servers.json,
# regenerated daily by the proton-updater GH Actions workflow).
# Nothing to download at pod boot — just lay out the OpenVPN config
# dir the runtime writes into.
#
set -e

CONFIG_DIR="/etc/protonvpn/openvpn"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

echo "ProtonVPN config directory ready: $CONFIG_DIR"
