#!/usr/bin/env bash
set -e

# Source .env file if present (for credentials)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  echo "[run.sh] Loading environment from $SCRIPT_DIR/.env"
  set -a
  source "$SCRIPT_DIR/.env"
  set +a
fi

CONFIG_FILE="$HOME/.config/tundler/tundler.yaml"
CFG_MOUNT=""
if [[ -f "$CONFIG_FILE" ]]; then
  echo "[run.sh] Using config file $CONFIG_FILE"
  CFG_MOUNT="-v $CONFIG_FILE:/home/tundler/tundler.yaml:ro"
fi
CONTAINER_NAME="tundler"
IMAGE_NAME="tundler"

echo "[run.sh] Checking for existing container..."

if docker ps -a --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; then
  echo "[run.sh] Stopping and removing existing container: $CONTAINER_NAME"
  docker rm -f "$CONTAINER_NAME"
fi

echo "[run.sh] Running $IMAGE_NAME container in background..."

docker run -it -d \
  --name "$CONTAINER_NAME" \
  $CFG_MOUNT \
  --privileged \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  --ulimit nofile=65536:65536 \
  --tmpfs /run \
  --tmpfs /run/lock \
  --tmpfs /tmp \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --cgroupns=host \
  -p 4242:4242 \
  -p 8484:8484 \
  -e EXPRESSVPN_ACTIVATION_CODE="${VPN_EXPRESSVPN_ACTIVATION_CODE:-$EXPRESSVPN_ACTIVATION_CODE}" \
  -e MULLVAD_ACCOUNT_NUMBER="${VPN_MULLVAD_ACCOUNT_NUMBER:-$MULLVAD_ACCOUNT_NUMBER}" \
  -e NORDVPN_TOKEN="${VPN_NORDVPN_TOKEN:-$NORDVPN_TOKEN}" \
  -e PRIVATEINTERNETACCESS_PASSWORD="${VPN_PRIVATEINTERNETACCESS_PASSWORD:-$PRIVATEINTERNETACCESS_PASSWORD}" \
  -e PRIVATEINTERNETACCESS_USERNAME="${VPN_PRIVATEINTERNETACCESS_USERNAME:-$PRIVATEINTERNETACCESS_USERNAME}" \
  -e SURFSHARK_OPENVPN_USERNAME="${VPN_SURFSHARK_OPENVPN_USERNAME:-$SURFSHARK_OPENVPN_USERNAME}" \
  -e SURFSHARK_OPENVPN_PASSWORD="${VPN_SURFSHARK_OPENVPN_PASSWORD:-$SURFSHARK_OPENVPN_PASSWORD}" \
  -e SURFSHARK_PROTOCOL="${VPN_SURFSHARK_PROTOCOL:-$SURFSHARK_PROTOCOL}" \
  -e SURFSHARK_WIREGUARD_PRIVATE_KEYS="${VPN_SURFSHARK_WIREGUARD_PRIVATE_KEYS:-$SURFSHARK_WIREGUARD_PRIVATE_KEYS}" \
  -e TUNDLER_NETNS=vpnns \
  -e TUNDLER_VPN_DNS="${VPN_TUNDLER_VPN_DNS:-$TUNDLER_VPN_DNS}" \
  "$IMAGE_NAME"
