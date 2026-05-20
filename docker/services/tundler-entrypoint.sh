#!/bin/bash
# Container PID 1 wrapper: forwards env to systemd, runs each installed
# provider's configure.sh once, then execs systemd as the real PID 1.

ENV_FILE="/etc/tundler/env"
mkdir -p "$(dirname "$ENV_FILE")"

# Export all relevant VPN provider env vars to the file
printenv | grep -E '^(EXPRESSVPN_|IPVANISH_|MULLVAD_|NORDVPN_|PRIVATEINTERNETACCESS_|PROTON_|SURFSHARK_|TUNDLER_)' > "$ENV_FILE"

# Run each installed provider's configure.sh once per pod boot. This
# downloads OpenVPN configs (ipvanish/protonvpn/surfshark), seeds CLI
# state, and otherwise prepares the provider for first-login. In the
# new per-provider images only one subdirectory exists under
# /opt/providers/ — the build-time install step deleted the others —
# so this loop runs exactly one configure.sh in production. Failures
# are logged but don't block boot: the tundler-tunnel service will
# crash + restart with a useful error message if configure.sh's
# output was required.
if [[ -d /opt/providers ]]; then
    for dir in /opt/providers/*/; do
        configure="$dir/configure.sh"
        if [[ -x "$configure" ]]; then
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

exec /lib/systemd/systemd
