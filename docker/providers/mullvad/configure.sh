#!/usr/bin/env bash
set -e

NETNS=${TUNDLER_NETNS:-vpnns}
SERVICE=mullvad-daemon

mkdir -p "/etc/systemd/system/${SERVICE}.d"
cat <<EOF >"/etc/systemd/system/${SERVICE}.d/netns.conf"
[Service]
NetworkNamespacePath=/var/run/netns/${NETNS}
EOF
systemctl daemon-reload
systemctl enable "${SERVICE}" --now

mullvad auto-connect set off
mullvad lan set allow

systemctl restart "${SERVICE}"
