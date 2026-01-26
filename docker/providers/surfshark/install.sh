#!/usr/bin/env bash
set -e

# Install OpenVPN and WireGuard for Surfshark connections
# No proprietary client needed - uses public API + standard VPN tools

apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    wireguard-tools \
    curl \
    ca-certificates
