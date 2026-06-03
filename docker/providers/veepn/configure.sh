#!/usr/bin/env bash
# OpenVPN-direct: nothing to configure at entrypoint time. Configs are
# baked, per-pod credentials arrive via env, the .ovpn is finalized
# lazily in tundler-tunnel's Connect() path.
set -e
exit 0
