#!/usr/bin/env bash
# Entrypoint-time configure.sh runs BEFORE systemd boots, so any
# `systemctl` / `warp-cli` calls here would fail (no DBus, daemon
# not running). WARP is fully driven from tundler-tunnel's
# Login()/Connect() paths once warp-svc.service is up — see
# internal/provider/warp/warp.go. Nothing to do here.
set -e
exit 0
