#!/usr/bin/env bash
set -euo pipefail

# Native HMA authentication and live server discovery are implemented in Go.
# OpenVPN uses device credentials and servers returned by the native API.
apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    iproute2 \
    iptables \
    curl \
    ca-certificates

mkdir -p /var/lib/tundler/hidemyass
chmod 700 /var/lib/tundler/hidemyass
