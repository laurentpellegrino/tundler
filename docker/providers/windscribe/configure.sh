#!/usr/bin/env bash
# OpenVPN-direct: nothing to configure at entrypoint time. CA + tls-auth
# are embedded, server list is fetched at runtime, the .ovpn is generated
# lazily in tundler-tunnel's Connect() path.
set -e
exit 0
