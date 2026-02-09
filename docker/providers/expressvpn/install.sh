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
apt-get install -y procps psmisc libatomic1 libglib2.0-0 libbrotli1

# Download & extract installer
mkdir -p "$WORKDIR"
cd "$WORKDIR"
curl -L -o "$FILENAME" "$URL"
chmod +x "$FILENAME"
"./$FILENAME" --noexec --nox11 --target "$WORKDIR/extracted"

# Manually install ExpressVPN files (the v5 multi_arch_installer.sh
# refuses to run in headless Docker environments)
SRCDIR="$WORKDIR/extracted/${ARCH}/expressvpnfiles"

if [[ ! -d "$SRCDIR" ]]; then
    echo "Expected directory not found: $SRCDIR"
    echo "Contents of extracted:"
    ls -la "$WORKDIR/extracted/" || true
    echo "Contents of extracted/${ARCH}:"
    ls -la "$WORKDIR/extracted/${ARCH}/" || true
    exit 1
fi

cd "$SRCDIR"

# Install main application to /opt/expressvpn
mkdir -p /opt/expressvpn
cp -dr bin lib plugins qml share /opt/expressvpn/

# Symlink binaries into PATH
for binary in /opt/expressvpn/bin/*; do
    ln -sf "$binary" "/usr/bin/$(basename "$binary")"
done

# Check for systemd service and sysusers files in the archive
EXTRACT_ROOT="$WORKDIR/extracted"
if find "$EXTRACT_ROOT" -name "expressvpn-service.service" -type f | head -1 | grep -q .; then
    cp "$(find "$EXTRACT_ROOT" -name "expressvpn-service.service" -type f | head -1)" /usr/lib/systemd/system/
fi
if find "$EXTRACT_ROOT" -name "expressvpn.conf" -path "*/sysusers.d/*" -type f | head -1 | grep -q .; then
    mkdir -p /usr/lib/sysusers.d
    cp "$(find "$EXTRACT_ROOT" -name "expressvpn.conf" -path "*/sysusers.d/*" -type f | head -1)" /usr/lib/sysusers.d/
fi

# Create systemd service if not provided in the archive
if [[ ! -f /usr/lib/systemd/system/expressvpn-service.service ]]; then
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

# Temporarily stub out systemctl to prevent service start during build
[[ -f $SYSTEMCTL_BAK ]] || { mv "$SYSTEMCTL" "$SYSTEMCTL_BAK"; ln -s /bin/true "$SYSTEMCTL"; }
trap 'rm -f "$SYSTEMCTL"; mv "$SYSTEMCTL_BAK" "$SYSTEMCTL"' EXIT

# Create expressvpn system user
systemd-sysusers

# Clean up extracted files
rm -rf "$WORKDIR/extracted" "$WORKDIR/$FILENAME"

# Verify installation
if ! command -v expressvpnctl >/dev/null 2>&1; then
    echo "ExpressVPN installation failed - expressvpnctl not found!"
    exit 1
fi

echo "ExpressVPN installation completed successfully!"
