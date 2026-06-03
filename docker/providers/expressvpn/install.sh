#!/usr/bin/env bash
set -euo pipefail

URL="https://www.expressvpn.works/clients/linux/expressvpn-linux-universal-14.1.1.13156_release.run"
FILENAME="expressvpn-installer.run"
WORKDIR="/home/tundler"
# Map uname arch to ExpressVPN archive directory names
case "$(uname -m)" in
    x86_64)  ARCH="x64" ;;
    aarch64) ARCH="arm64" ;;
    *)       echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

SYSTEMCTL="/usr/bin/systemctl"
SYSTEMCTL_BAK="/usr/bin/systemctl.real"

# Install runtime dependencies required by ExpressVPN v5
apt-get update
apt-get install -y procps psmisc libatomic1 libglib2.0-0 libbrotli1 libcap2-bin

# Download & extract installer
mkdir -p "$WORKDIR"
cd "$WORKDIR"
# ExpressVPN's CDN (expressvpn.works) serves a small HTML block/challenge
# page instead of the .run to some datacenter IPs (notably GitHub Actions
# runners — the block is per source IP, not per user-agent). The old
# `curl -L` didn't notice and the build then tried to EXECUTE that HTML
# as a shell script (`<!DOCTYPE HTML ...: syntax error`). Harden it: send
# a browser UA, retry with backoff (covers intermittent/per-runner
# blocks), and validate the result is the real makeself archive (sizeable,
# not starting with '<') — failing loudly with the block page's first
# bytes instead of running garbage.
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
download_installer() {
    local attempt sz first
    for attempt in 1 2 3 4; do
        if curl -fL --max-time 300 -A "$UA" -o "$FILENAME" "$URL"; then
            sz=$(stat -c%s "$FILENAME" 2>/dev/null || echo 0)
            first=$(head -c1 "$FILENAME" 2>/dev/null)
            if [ "$sz" -gt 1000000 ] && [ "$first" != "<" ]; then
                echo "ExpressVPN: downloaded installer ($sz bytes)"
                return 0
            fi
            echo "ExpressVPN: attempt $attempt got an invalid file (size=$sz, first='$first') — likely a CDN block page; retrying..."
        fi
        sleep $((attempt * 10))
    done
    echo "ERROR: could not download a valid ExpressVPN installer from $URL." >&2
    echo "       The CDN is likely blocking this host's IP with an HTML page. First bytes:" >&2
    head -c 300 "$FILENAME" >&2 || true
    return 1
}
# In CI the installer is prefetched on the runner THROUGH Cloudflare WARP
# (see .github/workflows/docker-image.yml + .github/actions/setup-cloudflare-warp)
# and dropped next to this script, because ExpressVPN's CDN serves a block
# page to GitHub Actions runner IPs. If that prefetched file is present and
# valid, use it; otherwise download directly (works on un-blocked IPs, e.g.
# local builds). Either way it's the official current .run from the CDN, not
# a frozen re-host.
PREFETCHED="$(dirname "$0")/expressvpn-prefetched.run"
if [ -f "$PREFETCHED" ] && [ "$(head -c1 "$PREFETCHED" 2>/dev/null)" != "<" ] \
   && [ "$(stat -c%s "$PREFETCHED" 2>/dev/null || echo 0)" -gt 1000000 ]; then
    echo "ExpressVPN: using WARP-prefetched installer ($(stat -c%s "$PREFETCHED") bytes)"
    cp "$PREFETCHED" "$FILENAME"
else
    download_installer
fi
chmod +x "$FILENAME"
"./$FILENAME" --noexec --nox11 --target "$WORKDIR/extracted"

# Manually install ExpressVPN files (the v5 multi_arch_installer.sh
# refuses to run in headless Docker environments)
ARCHDIR="$WORKDIR/extracted/${ARCH}"
SRCDIR="${ARCHDIR}/expressvpnfiles"

if [[ ! -d "$SRCDIR" ]]; then
    echo "Expected directory not found: $SRCDIR"
    ls -la "$WORKDIR/extracted/" || true
    ls -la "$ARCHDIR/" || true
    exit 1
fi

# Install main application to /opt/expressvpn
cp -a "$SRCDIR" /opt/expressvpn

# Create required runtime directories
mkdir -p /opt/expressvpn/{etc,var}

# Set capabilities on unbound binary
setcap 'cap_net_bind_service=+ep' /opt/expressvpn/bin/expressvpn-unbound

# Install additional files from installfiles/
if [[ -d "${ARCHDIR}/installfiles" ]]; then
    cp "${ARCHDIR}/installfiles/error-notice.sh" /opt/expressvpn/bin/ 2>/dev/null || true
fi

# Symlink CLI binaries into PATH
ln -sf /opt/expressvpn/bin/expressvpnctl /usr/bin/expressvpnctl
ln -sf /opt/expressvpn/bin/expressvpn-client /usr/bin/expressvpn-client

# Install systemd service from archive
if [[ -f "${ARCHDIR}/installfiles/expressvpn-service.service" ]]; then
    cp "${ARCHDIR}/installfiles/expressvpn-service.service" /usr/lib/systemd/system/
else
    # Fallback: create service manually
    cat > /usr/lib/systemd/system/expressvpn-service.service <<'EOF'
[Unit]
Description=ExpressVPN Daemon
After=network.target

[Service]
Type=simple
ExecStart=/opt/expressvpn/bin/expressvpn-daemon
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
fi

# Create expressvpn system groups
mkdir -p /usr/lib/sysusers.d
cat > /usr/lib/sysusers.d/expressvpn.conf <<'EOF'
g expressvpn - - -
g expressvpnhnsd - - -
EOF

# Temporarily stub out systemctl to prevent service start during build
[[ -f $SYSTEMCTL_BAK ]] || { mv "$SYSTEMCTL" "$SYSTEMCTL_BAK"; ln -s /bin/true "$SYSTEMCTL"; }
trap 'rm -f "$SYSTEMCTL"; mv "$SYSTEMCTL_BAK" "$SYSTEMCTL"' EXIT

# Create system groups
systemd-sysusers

# Clean up extracted files
rm -rf "$WORKDIR/extracted" "$WORKDIR/$FILENAME"

# Verify installation
if ! command -v expressvpnctl >/dev/null 2>&1; then
    echo "ExpressVPN installation failed - expressvpnctl not found!"
    exit 1
fi

echo "ExpressVPN installation completed successfully!"
