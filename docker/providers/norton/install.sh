#!/usr/bin/env bash
set -e

# Norton VPN runs as OpenVPN-direct (no provider daemon) — the Go binary spawns
# openvpn at connect time, authenticating with the per-device
# NORTON_USERNAME/NORTON_PASSWORD and the CA embedded in the binary. The exit
# server list is embedded too, so there is nothing to bake here.
apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    ca-certificates \
    curl
echo "norton: openvpn installed ($(openvpn --version 2>&1 | head -1))"
