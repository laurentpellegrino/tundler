#!/usr/bin/env bash
set -e

# CyberGhost runs as OpenVPN-direct (no provider daemon) — same
# pattern as protonvpn / surfshark. The Go binary spawns openvpn at
# connect time and reads the per-pod cert/key/user/pass from
# POD_<n>_* env vars (populated by the StatefulSet's envFrom of
# vpn-credentials-cyberghost).
#
# We do NOT bake server configs into the image at build time. The
# server list ships embedded inside the tundler-tunnel binary via
# go:embed (internal/provider/cyberghost/servers.json), refreshed
# daily by .github/workflows/update-cyberghost-servers.yml. The
# .ovpn config itself is generated at connect time from a template
# in cyberghost.go.

apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    ca-certificates \
    curl
echo "CyberGhost: openvpn installed ($(openvpn --version 2>&1 | head -1))"
