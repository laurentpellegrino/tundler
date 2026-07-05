#!/usr/bin/env bash
# Per-pod VPN-hub architecture:
#
#   - tundler-entrypoint.sh runs THIS script BEFORE systemd takes over
#     PID 1, so any `systemctl daemon-reload` / `--now` would fail with
#     "Failed to connect to bus: Host is down" (no d-bus yet). Writing
#     unit files / drop-ins is fine — systemd reads them when it boots.
#   - tundler-entrypoint.sh later DELETES every /etc/systemd/system/
#     *.service.d/netns.conf drop-in; our drop-in below uses a different
#     name so it survives.
#
# Network Lock (killswitch) MUST be off, and the only reliable way to
# guarantee it is to patch the daemon's settings.json BEFORE every daemon
# start: at the default "auto" the daemon arms an iptables firewall
# (evpn.* chains incl. blockDNS hooked into OUTPUT) during connect
# transitions, and its futex-deadlock bug can leave that firewall behind,
# blackholing the pod's entire egress+DNS. The CLI knob
# (`expressvpnctl set networklock off`, called in tundler's Login()) goes
# through the daemon's IPC — exactly the channel that wedges — so it is
# silently lost whenever the daemon is deadlocked. An ExecStartPre runs on
# EVERY daemon start, including tundler's login-free wedge-recovery
# restarts, with the daemon guaranteed not running.
cat > /usr/local/bin/expressvpn-prestart.sh <<'EOF'
#!/bin/sh
# Runs as ExecStartPre of expressvpn-service: force Network Lock off and
# clear any firewall left behind by a previous (deadlocked) daemon.
SETTINGS=/opt/expressvpn/etc/settings.json
if [ -f "$SETTINGS" ]; then
    sed -i 's/"killswitch":[[:space:]]*"[^"]*"/"killswitch": "off"/' "$SETTINGS"
else
    # First boot: the daemon creates the file with defaults on startup and
    # merges unknown/missing keys, so seeding just the one key is enough.
    mkdir -p "$(dirname "$SETTINGS")"
    printf '{\n    "killswitch": "off"\n}\n' > "$SETTINGS"
fi
# Clear ALL firewall damage a previous (deadlocked) daemon left behind.
# Observed 2026-07-05: 4 pods stuck 24h+ with 260+ consecutive login
# timeouts — the armed evpn.* chains blackholed every egress packet, so
# the login RPC (the only call that needs the backend) timed out while
# the status RPC (local IPC) kept answering. The old single
# `-D OUTPUT -j evpn.OUTPUT` here missed other jump forms and left the
# chains in place. This damage lives in the POD netns: it survives
# daemon AND container restarts; only pod deletion or this cleanup
# clears it. Safe here: the daemon is guaranteed not running during
# ExecStartPre, and it rebuilds the firewall on the next connect if it
# actually needs it.
for hook in INPUT OUTPUT FORWARD; do
    iptables -S "$hook" 2>/dev/null | grep evpn | sed 's/^-A/-D/' | while read -r rule; do
        # shellcheck disable=SC2086
        iptables $rule 2>/dev/null
    done
done
for c in $(iptables -S 2>/dev/null | awk '/^-N evpn/{print $2}'); do iptables -F "$c" 2>/dev/null; done
for c in $(iptables -S 2>/dev/null | awk '/^-N evpn/{print $2}'); do iptables -X "$c" 2>/dev/null; done
# Same class of damage, DNS layer: on connect the daemon rewrites
# /etc/resolv.conf to its in-tunnel resolver (100.64.100.1, reachable
# ONLY through the tunnel) and never restores it when the session dies.
# The file is bind-mounted from the pod sandbox, so it too survives
# container restarts. If names don't resolve with the tunnel down, fall
# back to public resolvers over eth0 so the daemon can reach its backend
# to log in; the daemon rewrites resolv.conf again on the next connect.
if ! timeout 4 getent hosts www.expressvpn.com >/dev/null 2>&1; then
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
fi
exit 0
EOF
chmod +x /usr/local/bin/expressvpn-prestart.sh

mkdir -p /etc/systemd/system/expressvpn-service.service.d
cat > /etc/systemd/system/expressvpn-service.service.d/10-killswitch-off.conf <<'EOF'
[Service]
ExecStartPre=/usr/local/bin/expressvpn-prestart.sh
EOF

# Make sure the daemon unit auto-starts when systemd boots. `systemctl
# enable` is pure symlink creation; it works offline without d-bus, so it
# is safe to call before /lib/systemd/systemd is exec'd.
#
# Exits 0 unconditionally — failures to enable would be diagnosed by
# systemd's own "Unit not found" / "Failed to start" later, far more
# informatively than this script's exit code.
systemctl enable expressvpn-service.service 2>/dev/null || true
exit 0
