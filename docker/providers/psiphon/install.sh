#!/usr/bin/env bash
set -e

# Psiphon is a proxy-chain provider: the tundler-tunnel binary spawns
# psiphon-client (the psiphon-tunnel-core ConsoleClient), which exposes a
# local HTTP CONNECT proxy that the in-process proxy chains through. No
# account / credentials. The client's network config (server-list signing
# key + bootstrap entries) is embedded in the Go binary.
#
# We bake the statically-linked psiphon-client binary from the
# `psiphon-client` GitHub release (built from Psiphon-Labs/psiphon-tunnel-core).
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl
BIN_URL="${PSIPHON_CLIENT_URL:-https://github.com/laurentpellegrino/tundler/releases/download/psiphon-client/psiphon-client.gz}"
curl -fsSL --max-time 120 "$BIN_URL" -o /tmp/psiphon-client.gz
gunzip -f /tmp/psiphon-client.gz
install -m 0755 /tmp/psiphon-client /usr/local/bin/psiphon-client
rm -f /tmp/psiphon-client
mkdir -p /var/lib/psiphon
echo "Psiphon: psiphon-client installed ($(/usr/local/bin/psiphon-client -version 2>&1 | head -1 || echo binary))"
