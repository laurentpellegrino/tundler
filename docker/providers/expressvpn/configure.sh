#!/usr/bin/env bash
# Per-pod VPN-hub architecture:
#
#   - tundler-entrypoint.sh runs THIS script BEFORE systemd takes over
#     PID 1, so any `systemctl daemon-reload` / `--now` would fail with
#     "Failed to connect to bus: Host is down" (no d-bus yet).
#   - tundler-entrypoint.sh later DELETES every /etc/systemd/system/
#     *.service.d/netns.conf drop-in, so writing one here is wasted.
#   - The expressvpn-daemon will be started by systemd at boot once
#     the unit is enabled (via the symlink farm in
#     /etc/systemd/system/multi-user.target.wants/).
#   - The tundler-tunnel Go binary calls `expressvpnctl background
#     enable` + `expressvpnctl set networklock false` in its Login()
#     after the daemon is up — so we don't need to here.
#
# All we still need to do at this point: make sure the systemd unit is
# enabled so it auto-starts when systemd boots. `systemctl enable` is
# pure symlink creation; it works offline without d-bus, so it's safe
# to call before /lib/systemd/systemd is exec'd.
#
# Exits 0 unconditionally — failures to enable would be diagnosed by
# systemd's own "Unit not found" / "Failed to start" later, far more
# informatively than this script's exit code.
systemctl enable expressvpn-service.service 2>/dev/null || true
exit 0
