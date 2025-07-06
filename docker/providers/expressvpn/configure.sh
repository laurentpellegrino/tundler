#!/usr/bin/env bash
set -e

# Start the ExpressVPN service
NETNS=${TUNDLER_NETNS:-vpnns}
SERVICE=expressvpn-service

# Place service in the VPN namespace
mkdir -p "/etc/systemd/system/${SERVICE}.d"
cat <<EOF >"/etc/systemd/system/${SERVICE}.d/netns.conf"
[Service]
NetworkNamespacePath=/var/run/netns/${NETNS}
EOF
systemctl daemon-reload
systemctl enable "${SERVICE}" --now

# Ensure background mode so CLI works without GUI
expressvpnctl background enable