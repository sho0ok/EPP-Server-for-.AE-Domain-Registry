#!/bin/bash
#
# EPP Server RPM Build Script
#
# This script:
# 1. Creates a Python virtual environment
# 2. Downloads and installs all dependencies (offline-capable)
# 3. Bundles everything into a source tarball
# 4. Builds a self-contained RPM
#
# The resulting RPM includes all Python packages - no internet needed on target server.
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
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

    local missing=""

    # Check Python
    if ! command -v ${PYTHON_BIN} &> /dev/null; then
        missing="${missing} python3"
    else
        PYTHON_VERSION=$(${PYTHON_BIN} -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        log_info "Python version: ${PYTHON_VERSION}"

        # Check minimum version using Python itself
        ${PYTHON_BIN} -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)" || {
            log_error "Python 3.9+ required, found ${PYTHON_VERSION}"
            exit 1
        }
    fi

    # Check pip
    if ! ${PYTHON_BIN} -m pip --version &> /dev/null; then
        missing="${missing} python3-pip"
    fi

    # Check venv module
    if ! ${PYTHON_BIN} -c "import venv" &> /dev/null; then
        missing="${missing} python3-venv"
    fi

    # Check rpmbuild
    if ! command -v rpmbuild &> /dev/null; then
        missing="${missing} rpm-build"
    fi

    # Check development libraries (needed to compile some packages)
    if ! pkg-config --exists libxml-2.0 2>/dev/null; then
        log_warn "libxml2-devel may be missing (needed for lxml)"
    fi

    if [ -n "$missing" ]; then
        log_error "Missing prerequisites:${missing}"
        echo ""
        echo "Install with:"
        echo "  dnf install${missing} libxml2-devel libxslt-devel openssl-devel gcc"
        exit 1
    fi

    log_info "All prerequisites satisfied"
}

# Clean previous build
clean_build() {
    log_step "Cleaning previous build..."

    rm -rf "${BUILD_DIR}"
    rm -rf ~/rpmbuild/SOURCES/${PACKAGE_NAME}-*.tar.gz
    rm -rf ~/rpmbuild/RPMS/*/${PACKAGE_NAME}-*.rpm
    rm -rf ~/rpmbuild/BUILD/${PACKAGE_NAME}-*

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
    log_info "Verifying installed packages..."
    pip list

    # Deactivate venv
    deactivate

    log_info "Virtual environment created with all dependencies"
}

# Download packages for offline installation (alternative method)
download_packages() {
    log_step "Downloading packages for offline use..."

    local PACKAGES_DIR="${BUILD_DIR}/packages"
    mkdir -p "${PACKAGES_DIR}"

    # Download all packages as wheels
    pip download \
        -r "${PROJECT_DIR}/requirements.txt" \
        -d "${PACKAGES_DIR}" \
        --python-version 3.9 \
        --only-binary=:all: \
        || pip download \
            -r "${PROJECT_DIR}/requirements.txt" \
            -d "${PACKAGES_DIR}"

    log_info "Downloaded packages to ${PACKAGES_DIR}"
    ls -la "${PACKAGES_DIR}"
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

    # Copy requirements
    cp "${PROJECT_DIR}/requirements.txt" "${DEST}/"

    # Create empty directories
    mkdir -p "${DEST}/logs"
    mkdir -p "${DEST}/run"
    mkdir -p "${DEST}/config/tls"

    log_info "Project files copied"
}

# Create source tarball
create_tarball() {
    log_step "Creating source tarball..."

    mkdir -p ~/rpmbuild/SOURCES

    cd "${BUILD_DIR}"
    tar -czvf ~/rpmbuild/SOURCES/${PACKAGE_NAME}-${VERSION}.tar.gz \
        ${PACKAGE_NAME}-${VERSION}

    log_info "Created ~/rpmbuild/SOURCES/${PACKAGE_NAME}-${VERSION}.tar.gz"

    # Show tarball contents summary
    echo ""
    log_info "Tarball contents:"
    tar -tzvf ~/rpmbuild/SOURCES/${PACKAGE_NAME}-${VERSION}.tar.gz | head -30
    echo "... (truncated)"
}

# Build RPM
build_rpm() {
    log_step "Building RPM package..."

    # Setup rpmbuild directory structure
    mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

    # Copy spec file
    cp "${PROJECT_DIR}/packaging/epp-server.spec" ~/rpmbuild/SPECS/

    # Build RPM
    rpmbuild -bb ~/rpmbuild/SPECS/epp-server.spec

    # Find the built RPM
    RPM_FILE=$(find ~/rpmbuild/RPMS -name "${PACKAGE_NAME}-${VERSION}*.rpm" | head -1)

    if [ -n "$RPM_FILE" ]; then
        # Copy to project directory
        cp "$RPM_FILE" "${PROJECT_DIR}/packaging/"

        log_info "RPM built successfully!"
        echo ""
        echo "RPM file: ${PROJECT_DIR}/packaging/$(basename $RPM_FILE)"
        echo ""

        # Show RPM info
        rpm -qip "$RPM_FILE"

        echo ""
        log_info "RPM contents (top-level):"
        rpm -qlp "$RPM_FILE" | grep -E "^/opt/epp-server/[^/]+$|^/etc|^/usr/bin"
    else
        log_error "RPM file not found!"
        exit 1
    fi
}

# Show final instructions
show_instructions() {
    log_step "Build Complete!"

    echo ""
    echo "To install on target server:"
    echo ""
    echo "  1. Copy RPM to server:"
    echo "     scp packaging/${PACKAGE_NAME}-${VERSION}*.rpm user@server:/tmp/"
    echo ""
    echo "  2. Install Oracle Instant Client (if not installed):"
    echo "     dnf install oracle-instantclient-basic"
    echo ""
    echo "  3. Install EPP Server:"
    echo "     dnf install /tmp/${PACKAGE_NAME}-${VERSION}*.rpm"
    echo ""
    echo "  4. Configure and start (see post-install instructions)"
    echo ""
}

# Main
main() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     EPP Server RPM Build Script            ║${NC}"
    echo -e "${GREEN}║     Version: ${VERSION}                          ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
    echo ""

    check_prerequisites
    clean_build
    create_venv
    copy_project_files
    create_tarball
    build_rpm
    show_instructions
}

# Run main
main "$@"
