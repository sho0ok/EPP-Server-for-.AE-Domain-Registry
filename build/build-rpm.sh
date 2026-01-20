#!/bin/bash
#
# EPP Server RPM Build Script
# Run on RHEL 9+ or compatible system
#

set -e

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$SCRIPT_DIR/rpmbuild"
SOURCES_DIR="$BUILD_DIR/SOURCES"

echo "=========================================="
echo "EPP Server RPM Builder"
echo "Version: $VERSION"
echo "=========================================="
echo ""

# Check if running on RHEL 9+
if [ -f /etc/redhat-release ]; then
    RHEL_VERSION=$(cat /etc/redhat-release | grep -oP '\d+' | head -1)
    if [ "$RHEL_VERSION" -lt 9 ]; then
        echo "Error: RHEL 9+ required. Found RHEL $RHEL_VERSION"
        exit 1
    fi
else
    echo "Warning: Not running on RHEL. Build may fail."
fi

# Install build dependencies
echo "[1/6] Installing build dependencies..."
dnf install -y rpm-build python3 python3-pip python3-devel gcc openssl-devel \
    libffi-devel 2>/dev/null || yum install -y rpm-build python3 python3-pip \
    python3-devel gcc openssl-devel libffi-devel

# Create build directory structure
echo "[2/6] Creating build directories..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$SOURCES_DIR"/{src,config,scripts,systemd,venv}

# Copy source code
echo "[3/6] Copying source code..."
cp -r "$PROJECT_DIR/src"/* "$SOURCES_DIR/src/"
cp "$PROJECT_DIR/config/epp.yaml" "$SOURCES_DIR/config/"
cp "$PROJECT_DIR/config/logging.yaml" "$SOURCES_DIR/config/"

# Copy scripts
cp "$SCRIPT_DIR/rpm/SCRIPTS/generate-certs.sh" "$SOURCES_DIR/scripts/"
cp "$SCRIPT_DIR/rpm/SCRIPTS/epp-server-cli" "$SOURCES_DIR/scripts/"

# Copy systemd service
cp "$SCRIPT_DIR/rpm/SOURCES/systemd/epp-server.service" "$SOURCES_DIR/systemd/"

# Create virtual environment with all dependencies
echo "[4/6] Creating virtual environment with dependencies..."
python3 -m venv "$SOURCES_DIR/venv"
source "$SOURCES_DIR/venv/bin/activate"
pip install --upgrade pip wheel
pip install lxml oracledb cryptography pyyaml python-dateutil
deactivate

# Copy spec file
echo "[5/6] Preparing RPM spec..."
cp "$SCRIPT_DIR/rpm/SPECS/epp-server.spec" "$BUILD_DIR/SPECS/"

# Build RPM
echo "[6/6] Building RPM..."
rpmbuild --define "_topdir $BUILD_DIR" \
         --define "_sourcedir $SOURCES_DIR" \
         -bb "$BUILD_DIR/SPECS/epp-server.spec"

# Copy RPM to dist folder
mkdir -p "$PROJECT_DIR/dist"
cp "$BUILD_DIR/RPMS/x86_64/"*.rpm "$PROJECT_DIR/dist/"

echo ""
echo "=========================================="
echo "Build complete!"
echo "=========================================="
echo ""
echo "RPM file: $PROJECT_DIR/dist/epp-server-$VERSION-1.el9.x86_64.rpm"
echo ""
echo "To install:"
echo "  dnf install ./epp-server-$VERSION-1.el9.x86_64.rpm"
echo ""
