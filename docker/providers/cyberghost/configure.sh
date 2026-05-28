#!/usr/bin/env bash
# Entrypoint-time configure.sh runs BEFORE systemd boots. CyberGhost
# needs nothing at this stage — server list is embedded in the Go
# binary, CA cert is embedded too, per-pod credentials arrive via env
# from the StatefulSet's envFrom. Everything is set up lazily inside
# tundler-tunnel's Login() / Connect() paths at runtime.
set -e
exit 0
