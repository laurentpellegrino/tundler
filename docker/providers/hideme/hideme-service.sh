#!/usr/bin/env bash
# Runs the hide.me client in service mode for tundler-tunnel.
#
# - leak protection off: with it on, every packet that is not tunneled
#   is dropped while the tunnel is down, the pod's probe and control
#   traffic included; tundler-tunnel's exit-ip check covers leaks;
# - IPv4 only: the exit the runtime reports is IPv4;
# - the cluster CIDR bypasses the tunnel, as the main-table route the
#   entrypoint installs does for every other provider (the client's
#   rule sends all traffic to its own table first).
set -euo pipefail

if [[ -r /etc/tundler/env ]]; then
    # shellcheck disable=SC1091
    set -a; . /etc/tundler/env; set +a
fi

# A crashed earlier run may have left its rules and interface behind;
# the client cannot set up over them.
while ip rule del table 55555 2>/dev/null; do :; done
while ip -6 rule del table 55555 2>/dev/null; do :; done
ip link del vpn 2>/dev/null || true

mkdir -p /run/hide.me

args=(--caddr /run/hide.me/hide.me.sock
      --ca /opt/hide.me/CA.pem
      --tokenFile /var/lib/hideme/accessToken.txt
      --kill-switch=false
      --ipv4-only
      --rest-timeout 20s)
if [[ -n "${TUNDLER_CLUSTER_BYPASS_CIDR:-}" ]]; then
    args+=(--split-tunnel "$TUNDLER_CLUSTER_BYPASS_CIDR")
fi
exec /opt/hide.me/hide.me "${args[@]}" service
