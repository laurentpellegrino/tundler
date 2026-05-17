#!/usr/bin/env bash
set -e

# Install OpenVPN for IPVanish connections.
# IPVanish has no Linux CLI; we use its official OpenVPN configs.zip.
apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    curl \
    ca-certificates \
    unzip
