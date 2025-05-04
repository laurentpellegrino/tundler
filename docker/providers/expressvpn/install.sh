#!/usr/bin/env bash
set -euo pipefail

URL="https://www.expressvpn.com/fr/oneaccount/api/download/xv-linux-universal-4.0.1.9292.run?platform=linux"
FILENAME="expressvpn-installer.run"
WORKDIR="/home/tundler"

SYSTEMCTL="/usr/bin/systemctl"
SYSTEMCTL_BAK="/usr/bin/systemctl.real"

# Download & unpack installer
mkdir -p "$WORKDIR"
cd "$WORKDIR"
curl -L -o "$FILENAME" "$URL"
chmod +x "$FILENAME"
"./$FILENAME" --noexec --target "$WORKDIR"

# Temporarily stub out systemctl
[[ -f $SYSTEMCTL_BAK ]] || { mv "$SYSTEMCTL" "$SYSTEMCTL_BAK"; ln -s /bin/true "$SYSTEMCTL"; }
trap 'rm -f "$SYSTEMCTL"; mv "$SYSTEMCTL_BAK" "$SYSTEMCTL"' EXIT

# Run ExpressVPN multi-arch installer as tundler
sudo -u tundler "$WORKDIR/multi_arch_installer.sh" --systemd
