#!/usr/bin/env bash
set -e

# ProtonVPN is handled through standard OpenVPN. Server metadata is refreshed
# in configure.sh and again at runtime if the cache is missing.
apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    curl \
    ca-certificates
