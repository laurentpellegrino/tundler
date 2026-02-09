#!/usr/bin/env bash
set -e

NETNS=${TUNDLER_NETNS:-vpnns}
SERVICE=piavpn

# Configure PIA daemon to run in network namespace
mkdir -p "/etc/systemd/system/${SERVICE}.service.d"
cat <<EOF >"/etc/systemd/system/${SERVICE}.service.d/netns.conf"
[Service]
NetworkNamespacePath=/var/run/netns/${NETNS}
BindPaths=/etc/resolv.conf.vpnns:/etc/resolv.conf
EOF

systemctl daemon-reload
systemctl enable "${SERVICE}" --now

# CLI commands must run inside the VPN namespace to reach the daemon
ip netns exec "${NETNS}" piactl background enable
ip netns exec "${NETNS}" piactl set allowlan enable || true
ip netns exec "${NETNS}" piactl set debuglogging enable || true

# Restart the service to ensure clean state
systemctl restart "${SERVICE}" || true
