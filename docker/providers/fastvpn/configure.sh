#!/usr/bin/env bash
# Entrypoint-time configure.sh runs BEFORE systemd boots. FastVPN
# needs nothing at this stage — configs are baked into the image,
# credentials arrive via env from the StatefulSet's envFrom.
# Everything is set up lazily inside tundler-tunnel's Login() /
# Connect() paths at runtime.
set -e
exit 0
