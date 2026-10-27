#!/usr/bin/env bash
set -e

# FastVPN runs as OpenVPN-direct (no provider daemon). Per-pod
# credentials come from env (FASTVPN_USERNAME / FASTVPN_PASSWORD)
# populated by the StatefulSet's envFrom of vpn-credentials-fastvpn.
#
# Server configs ship as a daily-refreshed zip baked into the image
# at build time — sourced from the `fastvpn-configs` GitHub release
# tag, which is itself a mirror of
# https://vpn.ncapi.io/groupedServerList.zip (TCP and UDP configs,
# flattened), refreshed daily by
# .github/workflows/update-fastvpn-configs.yml.
#
# Each .ovpn carries multiple `remote ...` lines + `remote-random`,
# so openvpn handles edge-IP load-balancing client-side. Our Go
# provider picks ONE .ovpn (one city, the protocol its transport
# needs) per Connect() call and rewrites only its `auth-user-pass`
# directive, plus a `socks-proxy` line in warp mode.

apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    ca-certificates \
    curl \
    gpg \
    iproute2 \
    unzip
echo "FastVPN: openvpn installed ($(openvpn --version 2>&1 | head -1))"

# FastVPN's outer connection rides Cloudflare WARP in proxy mode
# (WLVPN's edge blocks datacenter IPs; WARP's local SOCKS5 proxy
# presents a Cloudflare source IP so the connection is accepted).
# Install the WARP client here so the provider can bring the proxy
# up at runtime — see the package doc in
# internal/provider/fastvpn/fastvpn.go.
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
  | gpg --yes --dearmor \
      --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ jammy main" \
  > /etc/apt/sources.list.d/cloudflare-client.list
apt-get update
apt-get install -y --no-install-recommends cloudflare-warp
echo "FastVPN: WARP transport installed ($(warp-cli --version 2>&1 | head -1))"

# Soft-fail download: if the release isn't reachable at build time
# (fresh repo with no first release yet, network blip), keep going
# — the runtime will simply find no configs and the pod will fail
# loudly at Login() time rather than producing a half-working image.
CONFIGS_URL="${FASTVPN_CONFIGS_URL:-https://github.com/laurentpellegrino/tundler/releases/download/fastvpn-configs/fastvpn-configs.zip}"
CONFIG_DIR=/etc/fastvpn/configs
TMP_ZIP="$(mktemp)"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

if curl -fsSL --max-time 120 "$CONFIGS_URL" -o "$TMP_ZIP"; then
    unzip -oq "$TMP_ZIP" -d "$CONFIG_DIR"
    rm -f "$TMP_ZIP"
    n_tcp=$(find "$CONFIG_DIR" -maxdepth 1 -name 'NCVPN-*-TCP.ovpn' | wc -l)
    n_udp=$(find "$CONFIG_DIR" -maxdepth 1 -name 'NCVPN-*-UDP.ovpn' | wc -l)
    echo "FastVPN: baked $n_tcp TCP + $n_udp UDP server configs from $CONFIGS_URL into image."
else
    rm -f "$TMP_ZIP"
    echo "FastVPN: WARN — could not fetch $CONFIGS_URL; runtime will need configs mounted some other way."
fi
