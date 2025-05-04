#!/usr/bin/env bash
set -e

sh <(curl -sSf https://downloads.nordcdn.com/apps/linux/install.sh) -n
groupadd -f nordvpn
usermod -aG nordvpn root
