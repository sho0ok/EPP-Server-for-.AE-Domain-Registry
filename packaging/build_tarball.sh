#!/bin/bash
#
# EPP Server Tarball Build Script
#
# Creates a self-contained tarball with bundled Python virtual environment.
# This can be:
# 1. Used directly for deployment (extract to /opt/epp-server)
# 2. Used to build an RPM on a machine with rpmbuild installed
#
# No rpmbuild required - just Python with pip and venv.
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
DIST_DIR="${PROJECT_DIR}/dist"
VERSION="1.0.0"
PACKAGE_NAME="epp-server"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."

    # Check Python
    if ! command -v ${PYTHON_BIN} &> /dev/null; then
        log_error "Python3 not found"
        exit 1
    fi

    PYTHON_VERSION=$(${PYTHON_BIN} -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    log_info "Python version: ${PYTHON_VERSION}"

    # Check minimum version
    ${PYTHON_BIN} -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)" || {
        log_error "Python 3.9+ required, found ${PYTHON_VERSION}"
        exit 1
    }

    # Check pip
    if ! ${PYTHON_BIN} -m pip --version &> /dev/null; then
        log_error "pip not found"
        exit 1
    fi

    # Check venv module
    if ! ${PYTHON_BIN} -c "import venv" &> /dev/null; then
        log_error "venv module not found"
        exit 1
    fi

    log_info "All prerequisites satisfied"
}

# Clean previous build
clean_build() {
    log_step "Cleaning previous build..."

    rm -rf "${BUILD_DIR}"
    rm -rf "${DIST_DIR}"
    mkdir -p "${DIST_DIR}"

    log_info "Clean complete"
}

# Create virtual environment and install dependencies
create_venv() {
    log_step "Creating virtual environment with bundled dependencies..."

    local VENV_DIR="${BUILD_DIR}/${PACKAGE_NAME}-${VERSION}/venv"

    mkdir -p "${BUILD_DIR}/${PACKAGE_NAME}-${VERSION}"

    # Create virtual environment
    log_info "Creating virtual environment..."
    ${PYTHON_BIN} -m venv "${VENV_DIR}"

    # Activate venv
    source "${VENV_DIR}/bin/activate"

    # Upgrade pip
    log_info "Upgrading pip..."
    pip install --upgrade pip wheel setuptools

    # Install dependencies
    log_info "Installing dependencies from requirements.txt..."
    pip install -r "${PROJECT_DIR}/requirements.txt"

    # Verify installations
    log_info "Installed packages:"
    pip list

    # Deactivate venv
    deactivate

    log_info "Virtual environment created with all dependencies"
}

# Copy project files
copy_project_files() {
    log_step "Copying project files..."

    local DEST="${BUILD_DIR}/${PACKAGE_NAME}-${VERSION}"

    # Copy source code
    cp -r "${PROJECT_DIR}/src" "${DEST}/"

    # Copy configuration
    cp -r "${PROJECT_DIR}/config" "${DEST}/"

    # Copy systemd service
    mkdir -p "${DEST}/systemd"
    cp "${PROJECT_DIR}/systemd/epp-server.service" "${DEST}/systemd/"

    # Copy scripts
    mkdir -p "${DEST}/scripts"
    cp "${PROJECT_DIR}/scripts/generate_certs.sh" "${DEST}/scripts/"
    chmod +x "${DEST}/scripts/generate_certs.sh"

    # Copy packaging files (for building RPM later)
    mkdir -p "${DEST}/packaging"
    cp "${PROJECT_DIR}/packaging/epp-server.spec" "${DEST}/packaging/"

    # Copy documentation
    cp "${PROJECT_DIR}/requirements.txt" "${DEST}/"
    cp "${PROJECT_DIR}/README.md" "${DEST}/"
    cp "${PROJECT_DIR}/PROGRESS.md" "${DEST}/"

    # Create empty directories
    mkdir -p "${DEST}/logs"
    mkdir -p "${DEST}/run"
    mkdir -p "${DEST}/config/tls"

    # Create install script
    cat > "${DEST}/install.sh" << 'INSTALL_EOF'
#!/bin/bash
#
# EPP Server Installation Script
# Run as root to install to /opt/epp-server
#

set -e

INSTALL_DIR="/opt/epp-server"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./install.sh)"
    exit 1
fi

echo "Installing EPP Server to ${INSTALL_DIR}..."

# Create epp user
if ! getent group epp >/dev/null; then
    groupadd -r epp
    echo "Created group: epp"
fi

if ! getent passwd epp >/dev/null; then
    useradd -r -g epp -d ${INSTALL_DIR} -s /sbin/nologin -c "EPP Server" epp
    echo "Created user: epp"
fi

# Create install directory
mkdir -p ${INSTALL_DIR}

# Copy files
echo "Copying files..."
cp -r "${SCRIPT_DIR}/src" ${INSTALL_DIR}/
cp -r "${SCRIPT_DIR}/venv" ${INSTALL_DIR}/
cp -r "${SCRIPT_DIR}/config" ${INSTALL_DIR}/
cp -r "${SCRIPT_DIR}/scripts" ${INSTALL_DIR}/
cp "${SCRIPT_DIR}/requirements.txt" ${INSTALL_DIR}/
cp "${SCRIPT_DIR}/README.md" ${INSTALL_DIR}/

# Create directories
mkdir -p ${INSTALL_DIR}/logs
mkdir -p ${INSTALL_DIR}/run
mkdir -p ${INSTALL_DIR}/config/tls

# Fix venv paths
echo "Fixing virtual environment paths..."
find ${INSTALL_DIR}/venv/bin -type f -exec \
    sed -i "s|${SCRIPT_DIR}/venv|${INSTALL_DIR}/venv|g" {} \; 2>/dev/null || true

# Set ownership
chown -R root:root ${INSTALL_DIR}
chown -R epp:epp ${INSTALL_DIR}/logs
chown -R epp:epp ${INSTALL_DIR}/run
chown epp:epp ${INSTALL_DIR}/config
chmod 750 ${INSTALL_DIR}/config
chmod 750 ${INSTALL_DIR}/config/tls

# Install systemd service
echo "Installing systemd service..."
cp "${SCRIPT_DIR}/systemd/epp-server.service" /etc/systemd/system/
systemctl daemon-reload

# Create wrapper script
cat > /usr/bin/epp-server << 'EOF'
#!/bin/bash
exec /opt/epp-server/venv/bin/python -m src.server "$@"
EOF
chmod +x /usr/bin/epp-server

echo ""
echo "=========================================="
echo "EPP Server installed successfully!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Configure Oracle connection:"
echo "   vi ${INSTALL_DIR}/config/epp.yaml"
echo ""
echo "2. Generate TLS certificates:"
echo "   ${INSTALL_DIR}/scripts/generate_certs.sh"
echo ""
echo "3. Set Oracle password:"
echo "   export ORACLE_PASSWORD='your_password'"
echo ""
echo "4. Enable and start service:"
echo "   systemctl enable epp-server"
echo "   systemctl start epp-server"
echo ""
INSTALL_EOF

    chmod +x "${DEST}/install.sh"

    log_info "Project files copied"
}

# Create tarball
create_tarball() {
    log_step "Creating distribution tarball..."

    cd "${BUILD_DIR}"

    # Create tarball
    tar -czvf "${DIST_DIR}/${PACKAGE_NAME}-${VERSION}.tar.gz" \
        ${PACKAGE_NAME}-${VERSION}

    log_info "Created ${DIST_DIR}/${PACKAGE_NAME}-${VERSION}.tar.gz"

    # Calculate size
    SIZE=$(du -h "${DIST_DIR}/${PACKAGE_NAME}-${VERSION}.tar.gz" | cut -f1)
    log_info "Tarball size: ${SIZE}"
}

# Show final instructions
show_instructions() {
    log_step "Build Complete!"

    echo ""
    echo "Distribution tarball created:"
    echo "  ${DIST_DIR}/${PACKAGE_NAME}-${VERSION}.tar.gz"
    echo ""
    echo "=========================================="
    echo "DEPLOYMENT OPTIONS"
    echo "=========================================="
    echo ""
    echo "Option 1: Direct Installation (recommended)"
    echo "-------------------------------------------"
    echo "  # Copy tarball to server"
    echo "  scp dist/${PACKAGE_NAME}-${VERSION}.tar.gz user@server:/tmp/"
    echo ""
    echo "  # On server (as root):"
    echo "  cd /tmp"
    echo "  tar -xzf ${PACKAGE_NAME}-${VERSION}.tar.gz"
    echo "  cd ${PACKAGE_NAME}-${VERSION}"
    echo "  ./install.sh"
    echo ""
    echo "Option 2: Build RPM (requires rpmbuild)"
    echo "----------------------------------------"
    echo "  # On a machine with rpmbuild:"
    echo "  mkdir -p ~/rpmbuild/SOURCES"
    echo "  cp dist/${PACKAGE_NAME}-${VERSION}.tar.gz ~/rpmbuild/SOURCES/"
    echo "  rpmbuild -bb packaging/epp-server.spec"
    echo ""
}

# Main
main() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     EPP Server Tarball Build Script        ║${NC}"
    echo -e "${GREEN}║     Version: ${VERSION}                          ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
    echo ""

    check_prerequisites
    clean_build
    create_venv
    copy_project_files
    create_tarball
    show_instructions
}

# Run main
main "$@"
