#!/usr/bin/env bash
set -e

# proxylist is a proxy-chain provider: the tundler-tunnel binary forwards
# each crawler CONNECT through an operator-supplied upstream HTTP(S)
# CONNECT proxy (pure Go), so there is no VPN client to install. Only a
# CA bundle is needed to validate TLS to https:// upstreams.
apt-get update
apt-get install -y --no-install-recommends ca-certificates
echo "proxylist: proxy-chain provider — no VPN client, CA bundle ensured"
