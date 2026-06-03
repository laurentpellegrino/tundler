#!/usr/bin/env bash
set -e

# VeePN runs as OpenVPN-direct (no provider daemon). Per-pod
# credentials come from env (POD_<n>_VEEPN_USERNAME / _PASSWORD)
# populated by the StatefulSet's envFrom of vpn-credentials-veepn.
#
# Each VeePN location ships a fully self-contained .ovpn (own embedded
# CA + tls-auth + server IP — 135 distinct CAs), so we bake the actual
# upstream config files (not a template). They ship as a zip baked at
# build time from the `veepn-configs` GitHub release, refreshed by
# .github/workflows/update-veepn-configs.yml (a headless-browser login
# to VeePN's Cloudflare-gated dashboard that re-downloads "all configs").
# The Go provider picks one location's .ovpn per Connect() and rewrites
# only its bare `auth-user-pass` directive.

apt-get update
apt-get install -y --no-install-recommends \
    openvpn \
    ca-certificates \
    curl \
    unzip
echo "VeePN: openvpn installed ($(openvpn --version 2>&1 | head -1))"

# Soft-fail download: if the release isn't reachable at build time
# (fresh repo, network blip), keep going — the pod fails loudly at
# Login() rather than producing a half-working image.
CONFIGS_URL="${VEEPN_CONFIGS_URL:-https://github.com/laurentpellegrino/tundler/releases/download/veepn-configs/veepn-configs.zip}"
CONFIG_DIR=/etc/veepn/configs
TMP_ZIP="$(mktemp)"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

if curl -fsSL --max-time 120 "$CONFIGS_URL" -o "$TMP_ZIP"; then
    unzip -oq "$TMP_ZIP" -d "$CONFIG_DIR"
    rm -f "$TMP_ZIP"
    n=$(find "$CONFIG_DIR" -maxdepth 1 -name '*.veepn.com.ovpn' | wc -l)
    echo "VeePN: baked $n server configs from $CONFIGS_URL into image."
else
    rm -f "$TMP_ZIP"
    echo "VeePN: WARN — could not fetch $CONFIGS_URL; runtime will find no configs and fail loudly at Login()."
fi
