#!/usr/bin/env bash
set -euo pipefail

# hide.me runs through its official Linux client (GPL-2.0,
# github.com/eventure/hide.client.linux) in service mode; tundler-tunnel
# drives it over the client's control socket (internal/provider/hideme).
# The client does the WireGuard key exchange and sets up the interface
# itself, with netlink, so no wireguard-tools are needed.
HIDEME_VERSION="0.9.14"
HIDEME_SHA256="3e9d6842a95a2c91c6e91bdf86389cd74390dda491f206b5b07c402254a56d8f"
HIDEME_URL="https://github.com/eventure/hide.client.linux/releases/download/v${HIDEME_VERSION}/hide.me-linux-amd64-${HIDEME_VERSION}.tar.gz"

apt-get update
apt-get install -y --no-install-recommends curl ca-certificates

tmp=$(mktemp -d)
curl -fsSL --retry 3 --max-time 120 "$HIDEME_URL" -o "$tmp/hide.me.tar.gz"
echo "${HIDEME_SHA256}  $tmp/hide.me.tar.gz" | sha256sum -c -
mkdir -p /opt/hide.me
tar --no-same-owner -xzf "$tmp/hide.me.tar.gz" -C /opt/hide.me hide.me CA.pem
chmod 0755 /opt/hide.me/hide.me
rm -rf "$tmp"

# Bake the public server list (the one `hide.me list` prints) into the
# image; the daily image rebuild refreshes it.
mkdir -p /etc/hideme
curl -fsSL --retry 3 --max-time 60 "https://api.hide.me/v1/network/free/en" -o /etc/hideme/servers.json
if ! grep -q '"hostname"' /etc/hideme/servers.json; then
    echo "hide.me: ERROR - the server list has no servers" >&2
    exit 1
fi
echo "hide.me: client ${HIDEME_VERSION}, server list baked ($(wc -c < /etc/hideme/servers.json) bytes)"

install -m 0755 /opt/providers/hideme/hideme-service.sh /usr/local/bin/hideme-service.sh
install -m 0644 /opt/providers/hideme/hideme.service /etc/systemd/system/hideme.service
