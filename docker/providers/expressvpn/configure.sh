#!/usr/bin/env bash
set -e

# Start the ExpressVPN service
NETNS=${TUNDLER_NETNS:-vpnns}
SERVICE=expressvpn-service

# Place service in the VPN namespace
mkdir -p "/etc/systemd/system/${SERVICE}.service.d"
cat <<EOF >"/etc/systemd/system/${SERVICE}.service.d/netns.conf"
[Service]
NetworkNamespacePath=/var/run/netns/${NETNS}
BindPaths=/etc/resolv.conf.vpnns:/etc/resolv.conf
EOF
systemctl daemon-reload
systemctl enable "${SERVICE}" --now

# CLI commands must run inside the VPN namespace to reach the daemon
ip netns exec "${NETNS}" expressvpnctl background enable
ip netns exec "${NETNS}" expressvpnctl set networklock false
