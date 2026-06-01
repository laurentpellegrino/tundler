#!/usr/bin/env bash
set -e

# OVPN runs OpenVPN-direct (no daemon). Nothing to configure at boot beyond
# ensuring the directory the provider writes its generated config +
# credentials into exists — the connect path builds the .ovpn per
# connection from the embedded CA/tls-auth + a server from the baked list.
mkdir -p /etc/ovpn/openvpn
