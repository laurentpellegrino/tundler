#!/usr/bin/env bash
set -e

# The surfshark-vpn CLI runs openvpn directly when connecting
# No systemd service needed - openvpn will run in the network namespace
# via the TUNDLER_NETNS environment variable handled by shared.RunCmd

# Pre-configure directories and skip interactive prompts
mkdir -p /root/.surfshark/credentials
mkdir -p /root/.surfshark/configs
mkdir -p /root/.surfshark/connectivity
mkdir -p /root/.surfshark/run
mkdir -p /root/.surfshark/tmp

# Disable error reporting prompt by setting config directly
echo '{"monitorAgreed":true}' > /root/.surfshark/user_config.json
