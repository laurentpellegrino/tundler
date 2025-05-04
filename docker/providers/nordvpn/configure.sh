#!/usr/bin/env bash
set -e

systemctl enable nordvpnd --now

nordvpn set lan-discovery enable
