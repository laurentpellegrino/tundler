#!/usr/bin/env bash
set -e

# Mullvad runs over wg-quick (no daemon). Nothing to configure at boot
# beyond ensuring the directory the provider writes wg0.conf into exists —
# the connect path builds the config per-connection from the pod's pinned
# key + a relay picked from Mullvad's public relay list.
mkdir -p /etc/mullvad/wireguard
