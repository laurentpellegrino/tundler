#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

IMAGE_NAME="tundler"
NO_CACHE=false
BUILD_ARGS=()
DOCKERFILE="$SCRIPT_DIR/Dockerfile"
CONTEXT_DIR="$SCRIPT_DIR/.."

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  -t, --tag <name[:tag]>   Image tag/name (default: ${IMAGE_NAME})
      --no-cache           Build without cache
      --build-arg KEY=VAL  Pass build-arg (repeatable)
  -f, --file <Dockerfile>  Dockerfile path (default: docker/Dockerfile)
  -C, --context <dir>      Build context directory (default: repo root)
  -h, --help               Show this help

Examples:
  $0 --no-cache --build-arg INSTALL_NORDVPN=false
  $0 -t tundler:dev -f docker/Dockerfile -C .
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--tag)
      IMAGE_NAME="$2"; shift 2;;
    --no-cache)
      NO_CACHE=true; shift;;
    --build-arg)
      BUILD_ARGS+=("--build-arg" "$2"); shift 2;;
    -f|--file)
      DOCKERFILE="$2"; shift 2;;
    -C|--context)
      CONTEXT_DIR="$2"; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown option: $1" >&2; usage; exit 2;;
  esac
done

# Basic sanity checks
if ! command -v docker >/dev/null 2>&1; then
  echo "[build.sh] Error: docker is not installed or not in PATH" >&2
  exit 1
fi

if [[ ! -f "$DOCKERFILE" ]]; then
  echo "[build.sh] Error: Dockerfile not found: $DOCKERFILE" >&2
  exit 1
fi

if [[ ! -d "$CONTEXT_DIR" ]]; then
  echo "[build.sh] Error: Build context directory not found: $CONTEXT_DIR" >&2
  exit 1
fi

cd -- "$CONTEXT_DIR"

echo "[build.sh] Building Docker image: $IMAGE_NAME"
echo "[build.sh] Dockerfile: $DOCKERFILE"
echo "[build.sh] Context: $(pwd)"

# Ensure BuildKit is enabled for --progress flag support
export DOCKER_BUILDKIT=1

ARGS=("--progress=plain" "-t" "$IMAGE_NAME" "-f" "$DOCKERFILE")
if [[ "$NO_CACHE" == true ]]; then
  ARGS+=("--no-cache")
fi

if [[ ${#BUILD_ARGS[@]} -gt 0 ]]; then
  ARGS+=("${BUILD_ARGS[@]}")
fi

docker build "${ARGS[@]}" .

echo "[build.sh] Done. Image built: $IMAGE_NAME"
