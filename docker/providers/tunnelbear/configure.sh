#!/usr/bin/env bash
set -e

# Nothing to configure: no daemon, no config files, no baked server list.
# The Go provider performs auth + edge selection at runtime.
echo "TunnelBear: nothing to configure"
