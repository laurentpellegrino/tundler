#!/usr/bin/env bash
#
# The ProtonVPN server catalog is baked into the image at build time
# (install.sh downloads servers.json from the protonvpn-servers GitHub
# release, refreshed daily by the update-proton-servers workflow). At
# runtime the provider writes each connection's config and management
# socket under a private tmpfs directory (/run/protonvpn); nothing to
# prepare here beyond checking the catalog is present.
#
set -e

SERVERS_FILE="${PROTON_SERVERS_FILE:-/etc/protonvpn/servers.json}"
if [[ ! -s "$SERVERS_FILE" ]]; then
    echo "ERROR: ProtonVPN catalog $SERVERS_FILE missing — broken image" >&2
    exit 1
fi
echo "ProtonVPN: catalog $SERVERS_FILE present ($(stat -c%s "$SERVERS_FILE") bytes, baked at build time)."
