#!/usr/bin/env bash
# Per-pod VPN-hub architecture:
#
#   - tundler-entrypoint.sh runs this BEFORE systemd takes over PID 1,
#     so any `systemctl daemon-reload` / `--now` would fail with
#     "Failed to connect to bus: Host is down".
#   - tundler-entrypoint.sh later deletes every netns.conf drop-in,
#     so writing one here is wasted.
#   - The piavpn daemon is started by systemd at boot once the unit
#     is enabled (symlink in /etc/systemd/system/multi-user.target.wants/).
#   - The tundler-tunnel Go binary handles `piactl background enable`
#     and runtime setup in its Login(), once the daemon is up.
#
# Only thing still useful here: `systemctl enable` — pure symlink
# creation, works offline without d-bus, safe to call before systemd
# is exec'd.
systemctl enable piavpn.service 2>/dev/null || true
exit 0
