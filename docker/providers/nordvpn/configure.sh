#!/usr/bin/env bash
set -e

NETNS=${TUNDLER_NETNS:-vpnns}
SERVICE=nordvpnd

mkdir -p "/etc/systemd/system/${SERVICE}.service.d"
cat <<EOF >"/etc/systemd/system/${SERVICE}.service.d/netns.conf"
[Service]
NetworkNamespacePath=/var/run/netns/${NETNS}
BindPaths=/etc/resolv.conf.vpnns:/etc/resolv.conf
EOF
systemctl daemon-reload
systemctl enable "${SERVICE}" --now

# CLI commands must run inside the VPN namespace to reach the daemon
ip netns exec "${NETNS}" nordvpn set analytics disabled
ip netns exec "${NETNS}" nordvpn set autoconnect disabled
ip netns exec "${NETNS}" nordvpn set firewall disabled
ip netns exec "${NETNS}" nordvpn set lan-discovery enable
ip netns exec "${NETNS}" nordvpn set pq on
ip netns exec "${NETNS}" nordvpn set technology NordLynx
