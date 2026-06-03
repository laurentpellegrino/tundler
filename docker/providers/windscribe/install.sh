#!/usr/bin/env bash
set -e

# Windscribe runs as OpenVPN-direct (no provider daemon). The shared
# OpenVPN credential comes from env (WINDSCRIBE_USERNAME / _PASSWORD,
# populated by the StatefulSet's envFrom of vpn-credentials-windscribe);
# Windscribe allows unlimited simultaneous connections, so all pods share
# one credential.
#
# No config archive is baked: the CA + tls-auth are embedded in the Go
# binary (go:embed), and the server list is fetched LIVE at Login() from
# Windscribe's public, no-auth API (assets.windscribe.com), with an
# embedded snapshot as fallback. So this image just needs openvpn.

apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    ca-certificates \
    curl
echo "Windscribe: openvpn installed ($(openvpn --version 2>&1 | head -1))"
