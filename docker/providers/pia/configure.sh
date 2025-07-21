#!/usr/bin/env bash
set -e

NETNS=${TUNDLER_NETNS:-vpnns}
SERVICE=piavpn

# Configure PIA daemon to run in network namespace
mkdir -p "/etc/systemd/system/${SERVICE}.d"
cat <<EOF >"/etc/systemd/system/${SERVICE}.d/netns.conf"
[Service]
NetworkNamespacePath=/var/run/netns/${NETNS}
EOF

systemctl daemon-reload
systemctl enable "${SERVICE}" --now

# Enable background mode to allow piactl to work without GUI
piactl background enable

piactl set allowlan enable || true
# Configure PIA settings for headless operation
piactl set debuglogging enable || true

# Restart the service to ensure clean state
systemctl restart "${SERVICE}" || true
