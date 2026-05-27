#!/usr/bin/env bash
set -e

# Install Cloudflare WARP consumer client (warp-cli + warp-svc).
# WARP runs as a systemd service (warp-svc.service) that maintains
# the anonymous registration + tunnel device; warp-cli talks to it.
#
# The package needs CAP_NET_ADMIN and /dev/net/tun — already
# granted by the StatefulSet template alongside the other VPN
# providers.
apt-get update
apt-get install -y --no-install-recommends \
    curl gpg ca-certificates

curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
  | gpg --yes --dearmor \
      --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

# Use jammy (22.04) repo — works on ubuntu:24.04 noble bases too,
# Cloudflare ship a single repo for current LTSes.
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ jammy main" \
  > /etc/apt/sources.list.d/cloudflare-client.list

apt-get update
apt-get install -y --no-install-recommends cloudflare-warp

echo "Cloudflare WARP installed: $(warp-cli --version 2>&1 | head -1)"
