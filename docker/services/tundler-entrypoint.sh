#!/bin/bash
# Container PID 1 wrapper: forwards env to systemd, runs each installed
# provider's configure.sh once, then execs systemd as the real PID 1.

ENV_FILE="/etc/tundler/env"
mkdir -p "$(dirname "$ENV_FILE")"

# Filter the container's process env down to what tundler-tunnel needs
# (and only that) before handing it to systemd via EnvironmentFile.
# systemd-managed services do NOT inherit container env by default —
# they get a clean environment plus whatever the unit declares. Anything
# not matched here is silently invisible to the Go binary.
#
# Categories matched:
#   POD_                — downward API (POD_NAME, POD_NAMESPACE)
#   EXPRESSVPN_, ...    — per-provider credentials
#   TUNDLER_            — pod identity + routing
#                          (TUNDLER_TUNNEL_PROVIDER, TUNDLER_TUNNEL_NODE_IP,
#                           TUNDLER_CLUSTER_BYPASS_CIDR, TUNDLER_PROXY_PORT,
#                           TUNDLER_PRERESOLVE_HOSTNAMES)
#   The tail alternation — explicit tundler-tunnel config knobs that
#                          don't share a common prefix yet. Each
#                          corresponds to a const in
#                          cmd/tundler-tunnel/main.go. Keep this list in
#                          sync when adding a new knob — otherwise the
#                          binary silently uses the compiled-in default
#                          and the operator wonders why the env var has
#                          no effect (see the 2026-05-26
#                          EXCLUDED_LOCATIONS=smart incident).
# Two alternation groups so the prefix entries (POD_, TUNDLER_, ...)
# match var names of any length while the explicit-name entries
# (EXCLUDED_LOCATIONS, ...) match exactly one var each. Without this
# split, a trailing '=' anchor on the union would have required
# 'TUNDLER_' to be followed immediately by '=' — turning TUNDLER_
# into a single literal var instead of a prefix.
printenv | grep -E '^(POD_|EXPRESSVPN_|FASTVPN_|IPVANISH_|MULLVAD_|NORDVPN_|OVPN_|PRIVATEINTERNETACCESS_|PROTON_|PUREVPN_|SURFSHARK_|TUNDLER_)|^(BOOT_LOGIN_JITTER_SECONDS|EXCLUDED_LOCATIONS|MIN_ROTATION_SECONDS|MAX_ROTATION_SECONDS|TUNNEL_WATCHDOG_INTERVAL_SECONDS|WEDGE_GUARD_THRESHOLD_SECONDS|ROTATION_RETRY_MAX|ROTATION_ATTEMPT_TIMEOUT_SECONDS)=' | sort > "$ENV_FILE"

# Run each installed provider's configure.sh once per pod boot. This
# downloads OpenVPN configs (fastvpn/protonvpn/surfshark), seeds CLI
# state, and otherwise prepares the provider for first-login. In the
# new per-provider images only one subdirectory exists under
# /opt/providers/ — the build-time install step deleted the others —
# so this loop runs exactly one configure.sh in production. Failures
# are logged but don't block boot: the tundler-tunnel service will
# crash + restart with a useful error message if configure.sh's
# output was required.
if [[ -d /opt/providers ]]; then
    for dir in /opt/providers/*/; do
        # Glob keeps the trailing slash on each match (e.g.
        # /opt/providers/pia/) — strip it so the configure path
        # doesn't end up with a double slash in log lines.
        dir="${dir%/}"
        configure="$dir/configure.sh"
        if [[ -x "$configure" ]]; then
            # Strip `ip netns exec <netns>` prefixes from configure.sh
            # before running it. The legacy scripts run their CLI setup
            # inside vpnns to reach the netns-pinned daemon — in the
            # per-pod architecture the daemon lives in the main netns,
            # so `ip netns exec` would fail to reach it and the script
            # would silently no-op (or hang). Stripping forces commands
            # to run in the main netns alongside the daemon.
            sed -E -i 's/ip netns exec [^[:space:]]+ //g' "$configure"
            echo "[tundler-entrypoint] running $configure"
            bash "$configure" || echo "[tundler-entrypoint] WARNING: $configure exited $?"
        fi
    done
fi

# Strip legacy netns-isolation systemd drop-ins. Each provider's
# configure.sh writes a netns.conf override pinning the VPN daemon to
# /var/run/netns/vpnns — useful in the LEGACY all-providers-in-one
# tundler image (where envoy ran inside the same container and needed
# netns separation), but obsolete in the per-pod VPN-hub architecture
# where the sibling envoy container shares the pod netns and the
# vpnns separation just routes VPN traffic into a dead-end namespace.
# Removing these makes provider daemons (nordvpnd, piavpn, etc.) run
# in the pod's main netns so they can actually establish tunnels.
rm -f /etc/systemd/system/*.service.d/netns.conf 2>/dev/null

# Install a cluster-CIDR routing exception BEFORE the VPN comes up.
#
# The VPN clients (expressvpn, openvpn-based, etc.) all use the split-
# default-route trick: instead of replacing the kernel default route,
# they add `0.0.0.0/1 via tun0` + `128.0.0.0/1 via tun0`. Together those
# eclipse the eth0 default for everything, so envoy's response packets
# to pods in the cluster (hub envoy at 10.0.115.254, etc.) would take
# the VPN tunnel out to the public internet → blackhole, hub envoy
# gets `upstream_cx_connect_timeout` and returns 503 to the crawler.
#
# Adding a /16 route via the eth0 gateway is MORE specific than /1, so
# the kernel picks it for traffic to cluster IPs. We do this BEFORE
# systemd boots so the route exists at the moment any VPN connect
# attempt rewrites the table. The route survives across rotations
# because the VPN client doesn't touch routes outside its own /1 split.
#
# TUNDLER_CLUSTER_BYPASS_CIDR is set by the StatefulSet template
# (see render-vpn-manifests.py). It MUST cover both the pod CIDR and
# the Service CIDR — typically a single /16 catches both in EKS/AKS/
# kubeadm clusters using contiguous 10.x.x.x allocations.
if [[ -n "$TUNDLER_CLUSTER_BYPASS_CIDR" ]]; then
    GW=$(ip route | awk '/^default /{print $3; exit}')
    if [[ -n "$GW" ]]; then
        # `ip route replace` is idempotent — succeeds whether the route
        # already exists (e.g. lingering from a previous container in
        # the same pod) or not. The old `ip route add` printed a
        # spurious WARNING on the "File exists" case even though the
        # route was correctly in place. Capture stderr on actual failure
        # so the warning is diagnostic, not opaque.
        ROUTE_ERR=$(ip route replace "$TUNDLER_CLUSTER_BYPASS_CIDR" via "$GW" dev eth0 onlink 2>&1) \
            && echo "[tundler-entrypoint] installed cluster-bypass route: $TUNDLER_CLUSTER_BYPASS_CIDR via $GW dev eth0" \
            || echo "[tundler-entrypoint] WARNING: failed to install cluster-bypass route $TUNDLER_CLUSTER_BYPASS_CIDR via $GW: $ROUTE_ERR"
    else
        echo "[tundler-entrypoint] WARNING: no eth0 default gateway found — cluster traffic may take the VPN path"
    fi
fi

exec /lib/systemd/systemd
