#!/usr/bin/env bash
set -euo pipefail

URL="https://www.expressvpn.works/clients/linux/expressvpn-linux-universal-5.1.0.12141_release.run"
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
curl -L -o "$FILENAME" "$URL"
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
