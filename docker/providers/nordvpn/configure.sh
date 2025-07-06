#!/usr/bin/env bash
set -e

NETNS=${TUNDLER_NETNS:-vpnns}
SERVICE=nordvpnd

mkdir -p "/etc/systemd/system/${SERVICE}.d"
cat <<EOF >"/etc/systemd/system/${SERVICE}.d/netns.conf"
[Service]
NetworkNamespacePath=/var/run/netns/${NETNS}
EOF
systemctl daemon-reload
systemctl enable "${SERVICE}" --now

nordvpn set analytics disabled
nordvpn set lan-discovery enable
nordvpn set pq on
nordvpn set technology NordLynx
