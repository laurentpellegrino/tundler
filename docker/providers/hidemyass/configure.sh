#!/usr/bin/env bash
set -euo pipefail

# No archive or account credentials are required at image-build time. Native
# device tokens and credentials are obtained by Login and kept private here.
STATE_DIR="${HIDEMYASS_STATE_DIR:-/var/lib/tundler/hidemyass}"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
