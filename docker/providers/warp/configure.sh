#!/usr/bin/env bash
# Runs at entrypoint time, BEFORE systemd boots — so it can only write
# files, not call warp-cli/systemctl (no DBus, daemon not up yet). The
# one thing it does: if a Zero Trust service token is present in the
# environment (sourced from OpenBao vpn/warp/teams via the
# ExternalSecret), write Cloudflare's managed-deployment config so the
# WARP daemon enrolls the device into the org using the token instead
# of an anonymous registration.
#
# Why this matters: anonymous `warp-cli registration new` is rate-limited
# by Cloudflare PER SOURCE IP, and Hetzner datacenter ranges are
# throttled hard — which is why warp crashlooped. Authenticated
# (service-token) enrollment is not subject to that anonymous throttle.
# See internal/provider/warp/warp.go (managedEnrollment).
set -e

WARP_DIR="/var/lib/cloudflare-warp"
MDM="${WARP_DIR}/mdm.xml"

if [[ -n "${WARP_ORGANIZATION:-}" && -n "${WARP_AUTH_CLIENT_ID:-}" && -n "${WARP_AUTH_CLIENT_SECRET:-}" ]]; then
    mkdir -p "$WARP_DIR"
    # Linux managed config is a bare <dict> plist (no <plist> wrapper).
    # auto_connect keeps the daemon enrolled+connected headlessly;
    # onboarding=false skips the first-run UI prompts.
    cat > "$MDM" <<EOF
<dict>
    <key>organization</key>
    <string>${WARP_ORGANIZATION}</string>
    <key>auth_client_id</key>
    <string>${WARP_AUTH_CLIENT_ID}</string>
    <key>auth_client_secret</key>
    <string>${WARP_AUTH_CLIENT_SECRET}</string>
    <key>service_mode</key>
    <string>warp</string>
    <key>onboarding</key>
    <false/>
    <key>auto_connect</key>
    <integer>1</integer>
</dict>
EOF
    chmod 600 "$MDM"
    echo "[warp-configure] wrote managed mdm.xml for org '${WARP_ORGANIZATION}' (authenticated enrollment)"
else
    echo "[warp-configure] no WARP_ORGANIZATION/service token in env — falling back to anonymous registration (rate-limited on datacenter IPs)"
fi

exit 0
