#!/usr/bin/env bash
#
# Entrypoint-time configure.sh runs BEFORE systemd boots, so any
# `systemctl …` or `nordvpn …` calls here fail (the daemon isn't up
# and there's no DBus). All nordvpnd configuration — analytics-
# consent dismissal, meshnet/notify off, NordLynx technology, etc.
# — is applied by tundler-tunnel's Login() in
# internal/provider/nordvpn/nordvpn.go (configureDaemon), where the
# daemon is guaranteed alive. Nothing to do here.
#
set -e
exit 0
