#!/usr/bin/env bash
set -e

# TunnelBear is a proxy-chain provider: the tundler-tunnel binary talks
# to TunnelBear's HTTPS CONNECT edges directly (pure Go), so there is no
# VPN client to install. We only need a CA bundle to validate TLS to the
# *.lazerpenguin.com edges and the PolarBear control-plane endpoints.
# The server list is NOT baked: it requires an authenticated PolarBear
# call, so the provider fetches it live at Connect time (no daily refresh
# workflow, unlike the OpenVPN/WireGuard providers).
apt-get update
apt-get install -y --no-install-recommends ca-certificates
echo "TunnelBear: proxy-chain provider — no VPN client, CA bundle ensured"
