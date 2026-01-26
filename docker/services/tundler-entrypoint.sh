#!/bin/bash
# Capture VPN provider environment variables before systemd takes over
# This allows new providers to be added without updating the systemd service

ENV_FILE="/etc/tundler/env"
mkdir -p "$(dirname "$ENV_FILE")"

# Export all relevant VPN provider env vars to the file
printenv | grep -E '^(EXPRESSVPN_|MULLVAD_|NORDVPN_|PRIVATEINTERNETACCESS_|SURFSHARK_|TUNDLER_)' > "$ENV_FILE"

exec /lib/systemd/systemd
