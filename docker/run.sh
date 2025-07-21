#!/usr/bin/env bash
set -e

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
  --tmpfs /run \
  --tmpfs /run/lock \
  --tmpfs /tmp \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --cgroupns=host \
  -p 4242:4242 \
  -p 8484:8484 \
  -e EXPRESSVPN_ACTIVATION_CODE="$EXPRESSVPN_ACTIVATION_CODE" \
  -e MULLVAD_ACCOUNT_NUMBER="$MULLVAD_ACCOUNT_NUMBER" \
  -e NORDVPN_TOKEN="$NORDVPN_TOKEN" \
  -e PRIVATEINTERNETACCESS_PASSWORD="$PRIVATEINTERNETACCESS_PASSWORD" \
  -e PRIVATEINTERNETACCESS_USERNAME="$PRIVATEINTERNETACCESS_USERNAME" \
  -e TUNDLER_NETNS=vpnns \
  "$IMAGE_NAME"
