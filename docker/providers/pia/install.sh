#!/usr/bin/env bash
set -e

# Install required dependencies
apt-get update
apt-get install -y curl wget ca-certificates sudo

echo "Fetching latest PIA version..."

# Get the latest version from PIA changelog page with better error handling
CHANGELOG_URL="https://www.privateinternetaccess.com/pages/changelog"
LATEST_VERSION=$(curl -s --max-time 30 "${CHANGELOG_URL}" | grep -oP 'pia-linux-\K[0-9]+\.[0-9]+\.[0-9]+-[0-9]+' | head -1 || echo "")

if [ -z "${LATEST_VERSION}" ]; then
    echo "Failed to fetch latest version, falling back to known version"
    LATEST_VERSION="3.7-08412"
fi

echo "Latest PIA version: ${LATEST_VERSION}"

# Detect architecture
ARCH=$(uname -m)
case "${ARCH}" in
    x86_64)
        PIA_URL="https://installers.privateinternetaccess.com/download/pia-linux-${LATEST_VERSION}.run"
        FALLBACK_URL="https://installers.privateinternetaccess.com/download/pia-linux-3.7-08412.run"
        ;;
    aarch64|arm64)
        PIA_URL="https://installers.privateinternetaccess.com/download/pia-linux-arm64-${LATEST_VERSION}.run"
        FALLBACK_URL="https://installers.privateinternetaccess.com/download/pia-linux-arm64-3.7-08412.run"
        ;;
    *)
        echo "Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

echo "Downloading PIA from: ${PIA_URL}"

# Download and install PIA Linux client with better error handling
if ! wget --timeout=60 --tries=3 -O /tmp/pia-installer.run "${PIA_URL}"; then
    echo "Download failed, trying fallback version..."
    if ! wget --timeout=60 --tries=3 -O /tmp/pia-installer.run "${FALLBACK_URL}"; then
        echo "Both download attempts failed!"
        exit 1
    fi
fi

# Verify the download
if [ ! -f /tmp/pia-installer.run ] || [ ! -s /tmp/pia-installer.run ]; then
    echo "Downloaded file is empty or missing!"
    exit 1
fi

chmod +x /tmp/pia-installer.run

# Create a temporary user to run the installer (PIA installer refuses to run as root)
useradd -m -s /bin/bash piauser || true
# Grant passwordless sudo access to piauser for installation
echo "piauser ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
chown piauser:piauser /tmp/pia-installer.run

# Run installer as non-root user with proper environment variables
export DEBIAN_FRONTEND=noninteractive

# The installer will fail at systemd service start, but that's expected in Docker build
# We'll capture the exit code and check if files were installed correctly
sudo -u piauser sh /tmp/pia-installer.run --accept --nox11 --quiet || {
    echo "Installer completed with systemd errors (expected in Docker build)"
    # Check if PIA files were actually installed despite systemd failure
    if [ ! -f /opt/piavpn/bin/piactl ]; then
        echo "Installation failed, trying interactive mode..."
        # Some versions might require interactive input
        echo -e "\ny\n" | sudo -u piauser sh /tmp/pia-installer.run || {
            echo "PIA installation failed completely!"
            exit 1
        }
    fi
}

# Clean up temporary user and sudo access
sed -i '/piauser ALL=(ALL) NOPASSWD: ALL/d' /etc/sudoers
userdel -rf piauser || true

rm -f /tmp/pia-installer.run

# Verify installation
if [ ! -f /opt/piavpn/bin/piactl ]; then
    echo "PIA installation verification failed - piactl not found!"
    exit 1
fi

# Ensure piactl is available in PATH
ln -sf /opt/piavpn/bin/piactl /usr/local/bin/piactl

echo "PIA installation completed successfully!"