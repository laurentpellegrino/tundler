#!/usr/bin/env bash
set -euo pipefail

curl -fsSLo /usr/share/keyrings/mullvad-keyring.asc https://repository.mullvad.net/deb/mullvad-keyring.asc
echo "deb [signed-by=/usr/share/keyrings/mullvad-keyring.asc arch=$( dpkg --print-architecture )] https://repository.mullvad.net/deb/stable stable main" | sudo tee /etc/apt/sources.list.d/mullvad.list

# The package's post-install script expects systemd and AppArmor
# directories to exist, so we create what is needed and provide a fake
# systemctl to avoid failures.

mkdir -p /etc/apparmor.d

# dummy systemctl used only during installation
mkdir -p /usr/local/bin
cat <<'EOF' >/usr/local/bin/systemctl
#!/bin/sh
echo "Skipping systemctl $*" >&2
exit 0
EOF
chmod +x /usr/local/bin/systemctl
export PATH=/usr/local/bin:$PATH

apt-get update
apt-get install -y mullvad-vpn

rm /usr/local/bin/systemctl

