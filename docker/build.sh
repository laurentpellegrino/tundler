#!/usr/bin/env bash
set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

IMAGE_NAME="tundler"

cd $SCRIPT_DIR/..

echo "[build.sh] Building Docker image..."
docker build --progress=plain --no-cache -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile" .

echo "[build.sh] Done. Image built: $IMAGE_NAME"
