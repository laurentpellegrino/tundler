#!/usr/bin/env bash
set -e

LOG=/var/log/tundler.log
echo "[TUNDLER] Running..." | tee -a "$LOG"

cd /opt/providers

for provider in *; do
  echo "Configuring $provider provider" | tee -a "$LOG"
  "./$provider/configure.sh" | tee -a "$LOG"
  echo "$provider configuration completed" | tee -a "$LOG"
done
