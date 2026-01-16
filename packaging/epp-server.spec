# EPP Server RPM Spec File
# Self-contained package with bundled Python virtual environment
#
# Build with: rpmbuild -bb epp-server.spec
# Requires: The build_rpm.sh script to prepare the source tarball

%define name epp-server
%define version 1.0.0
%define release 1%{?dist}
%define installdir /opt/epp-server

Name:           %{name}
Version:        %{version}
Release:        %{release}
Summary:        EPP Server for .AE Domain Registry

License:        Proprietary
URL:            https://aeda.ae
Source0:        %{name}-%{version}.tar.gz

# No auto-detection of dependencies - we bundle everything
AutoReqProv:    no

# System requirements (not Python packages - those are bundled)
Requires:       oracle-instantclient-basic >= 21.0
Requires:       systemd
Requires:       openssl

# Build requirements
BuildRequires:  python3 >= 3.9
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  python3-virtualenv
BuildRequires:  gcc
BuildRequires:  libxml2-devel
BuildRequires:  libxslt-devel
BuildRequires:  openssl-devel

%description
EPP (Extensible Provisioning Protocol) Server for the .AE domain registry.

Features:
- RFC 5730-5734 compliant EPP implementation
- TLS 1.2+ with client certificate authentication
- Oracle database backend (ARI schema)
- Full domain, contact, and host management
- Transfer workflow support
- Transaction logging

This package is self-contained with all Python dependencies bundled.

%prep
%setup -q

%build
# Nothing to build - venv is pre-built in the tarball

%install
rm -rf %{buildroot}

# Create directory structure
mkdir -p %{buildroot}%{installdir}
mkdir -p %{buildroot}%{installdir}/logs
mkdir -p %{buildroot}%{installdir}/run
mkdir -p %{buildroot}%{installdir}/config/tls
mkdir -p %{buildroot}/etc/systemd/system
mkdir -p %{buildroot}/usr/bin

# Copy application files
cp -r src %{buildroot}%{installdir}/
cp -r venv %{buildroot}%{installdir}/
cp -r config/* %{buildroot}%{installdir}/config/
cp requirements.txt %{buildroot}%{installdir}/

# Install systemd service
cp systemd/epp-server.service %{buildroot}/etc/systemd/system/

# Install scripts
mkdir -p %{buildroot}%{installdir}/scripts
cp scripts/generate_certs.sh %{buildroot}%{installdir}/scripts/

# Create wrapper script
cat > %{buildroot}/usr/bin/epp-server << 'EOF'
#!/bin/bash
# EPP Server wrapper script
exec /opt/epp-server/venv/bin/python -m src.server "$@"
EOF
chmod 755 %{buildroot}/usr/bin/epp-server

# Fix venv paths (they were built with a different prefix)
# Update the shebang in venv scripts
find %{buildroot}%{installdir}/venv/bin -type f -exec \
    sed -i 's|^#!.*/python|#!/opt/epp-server/venv/bin/python|' {} \; 2>/dev/null || true

# Update pyvenv.cfg
if [ -f %{buildroot}%{installdir}/venv/pyvenv.cfg ]; then
    sed -i 's|^home = .*|home = /usr/bin|' %{buildroot}%{installdir}/venv/pyvenv.cfg
fi

%pre
# Create epp user and group if they don't exist
getent group epp >/dev/null || groupadd -r epp
getent passwd epp >/dev/null || \
    useradd -r -g epp -d %{installdir} -s /sbin/nologin \
    -c "EPP Server Service Account" epp
exit 0

%post
# Set ownership
chown -R epp:epp %{installdir}/logs
chown -R epp:epp %{installdir}/run
chown -R epp:epp %{installdir}/config

# Set permissions on sensitive files
chmod 750 %{installdir}/config
chmod 750 %{installdir}/config/tls
chmod 640 %{installdir}/config/*.yaml 2>/dev/null || true

# Reload systemd
systemctl daemon-reload

echo ""
echo "=========================================="
echo "EPP Server installed successfully!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Configure Oracle connection:"
echo "   vi %{installdir}/config/epp.yaml"
echo ""
echo "2. Generate TLS certificates:"
echo "   %{installdir}/scripts/generate_certs.sh"
echo ""
echo "3. Set Oracle password (choose one method):"
echo "   export ORACLE_PASSWORD='your_password'"
echo "   # Or add to /etc/sysconfig/epp-server"
echo ""
echo "4. Enable and start service:"
echo "   systemctl enable epp-server"
echo "   systemctl start epp-server"
echo ""
echo "5. Check status:"
echo "   systemctl status epp-server"
echo "   journalctl -u epp-server -f"
echo ""

%preun
if [ $1 -eq 0 ]; then
    # Package removal (not upgrade)
    systemctl stop epp-server 2>/dev/null || true
    systemctl disable epp-server 2>/dev/null || true
fi

%postun
if [ $1 -eq 0 ]; then
    # Package removal (not upgrade)
    systemctl daemon-reload
fi

%files
%defattr(-,root,root,-)

# Application files
%{installdir}/src
%{installdir}/venv
%{installdir}/requirements.txt
%{installdir}/scripts

# Config files (marked as config so they're not overwritten on upgrade)
%config(noreplace) %{installdir}/config/epp.yaml
%config(noreplace) %{installdir}/config/logging.yaml
%dir %{installdir}/config/tls

# Directories owned by epp user
%attr(750,epp,epp) %dir %{installdir}/logs
%attr(750,epp,epp) %dir %{installdir}/run

# Systemd service
/etc/systemd/system/epp-server.service

# Wrapper script
/usr/bin/epp-server

%changelog
* %(date "+%a %b %d %Y") EPP Server Team <epp@aeda.ae> - 1.0.0-1
- Initial release
- Full EPP RFC 5730-5734 compliance
- Domain, contact, and host management
- Transfer workflow support
- Self-contained with bundled dependencies
