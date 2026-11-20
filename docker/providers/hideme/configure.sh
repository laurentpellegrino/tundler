#!/usr/bin/env bash
set -e

# The token directory must exist before tundler-tunnel logs in; the
# service reads the token from there and refreshes it in place.
mkdir -p /var/lib/hideme
chmod 0700 /var/lib/hideme
