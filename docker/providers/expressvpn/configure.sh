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
# Drop stale killswitch hooks from a previous daemon (idempotent).
while iptables -D OUTPUT -j evpn.OUTPUT 2>/dev/null; do :; done
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
