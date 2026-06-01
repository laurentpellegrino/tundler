#!/usr/bin/env bash
set -e

# PureVPN runs OpenVPN-direct (no daemon). Nothing to configure at boot
# beyond ensuring the directory the provider writes its generated config +
# credentials into exists.
mkdir -p /etc/purevpn/openvpn
