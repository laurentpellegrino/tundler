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

# Wait briefly for the daemon to be reachable on its socket.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    nordvpn status >/dev/null 2>&1 && break
    sleep 1
done

# Decline the analytics-consent prompt that nordvpn-cli started
# shipping in recent versions. Without this, every subsequent
# `nordvpn` call hangs waiting for stdin "y/n". Piping "n" once
# dismisses the prompt permanently and sets analytics to disabled,
# which is what we want operationally anyway.
echo "n" | nordvpn login 2>/dev/null || true

# CLI commands must run inside the VPN namespace to reach the daemon
ip netns exec "${NETNS}" nordvpn set analytics disabled
ip netns exec "${NETNS}" nordvpn set autoconnect disabled
ip netns exec "${NETNS}" nordvpn set firewall disabled
ip netns exec "${NETNS}" nordvpn set lan-discovery enable
ip netns exec "${NETNS}" nordvpn set pq on
ip netns exec "${NETNS}" nordvpn set technology NordLynx
