#!/usr/bin/env bash
set -e

NETNS=${TUNDLER_NETNS:-vpnns}
SERVICE=mullvad-daemon

# Disable Mullvad's early boot network blocker — it adds nftables rules in the
# default namespace that block all non-LAN traffic, breaking both the Envoy
# proxy and VPN namespace internet access. Tundler manages isolation itself.
systemctl disable mullvad-early-boot-blocking.service 2>/dev/null || true
systemctl stop mullvad-early-boot-blocking.service 2>/dev/null || true
nft delete table inet mullvad 2>/dev/null || true

mkdir -p "/etc/systemd/system/${SERVICE}.service.d"
cat <<EOF >"/etc/systemd/system/${SERVICE}.service.d/netns.conf"
[Service]
NetworkNamespacePath=/var/run/netns/${NETNS}
BindPaths=/etc/resolv.conf.vpnns:/etc/resolv.conf
EOF
systemctl daemon-reload
systemctl enable "${SERVICE}" --now

# CLI commands must run inside the VPN namespace to reach the daemon
ip netns exec "${NETNS}" mullvad auto-connect set off
ip netns exec "${NETNS}" mullvad lan set allow

systemctl restart "${SERVICE}"
