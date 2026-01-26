#!/usr/bin/env bash
set -e

# Install Surfshark VPN legacy CLI (headless-compatible)
# https://support.surfshark.com/hc/en-us/articles/360017418334-How-to-set-up-Surfshark-VPN-on-Linux-Legacy-version

apt-get update
apt-get install -y --no-install-recommends openvpn curl ca-certificates expect

curl -fsSL https://ocean.surfshark.com/debian/pool/main/s/surfshark-vpn_1.1.0_amd64.deb -o /tmp/surfshark-vpn.deb
dpkg -i /tmp/surfshark-vpn.deb || apt-get install -f -y
rm -f /tmp/surfshark-vpn.deb
