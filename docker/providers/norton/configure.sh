#!/usr/bin/env bash
set -e

# Norton VPN runs OpenVPN-direct (no daemon). Nothing to configure at boot
# beyond ensuring the directory the provider writes its generated config +
# credentials into exists — the connect path builds the .ovpn per connection
# from the embedded CA + an embedded server.
mkdir -p /etc/norton/openvpn
