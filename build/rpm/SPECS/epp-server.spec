Name:           epp-server
Version:        1.0.0
Release:        1%{?dist}
Summary:        EPP Server for .AE Domain Registry
License:        MIT
URL:            https://github.com/sho0ok/EPP-Server-for-.AE-Domain-Registry
BuildArch:      x86_64

Requires:       python3 >= 3.9
Requires:       openssl

%description
A production-ready EPP (Extensible Provisioning Protocol) server for .AE domain
registry operations. Supports RFC 5730-5734 with TLS 1.2+ security and Oracle
database backend.

%install
# Create directories
mkdir -p %{buildroot}/opt/epp-server
mkdir -p %{buildroot}/opt/epp-server/venv
mkdir -p %{buildroot}/etc/epp-server
mkdir -p %{buildroot}/etc/epp-server/tls
mkdir -p %{buildroot}/etc/systemd/system/epp-server.service.d
mkdir -p %{buildroot}/var/log/registryd
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib/systemd/system

# Copy application files
cp -r %{_sourcedir}/src %{buildroot}/opt/epp-server/
cp -r %{_sourcedir}/venv/* %{buildroot}/opt/epp-server/venv/

# Copy config files
cp %{_sourcedir}/config/epp.yaml %{buildroot}/etc/epp-server/
cp %{_sourcedir}/config/logging.yaml %{buildroot}/etc/epp-server/

# Copy scripts
cp %{_sourcedir}/scripts/generate-certs.sh %{buildroot}/usr/bin/epp-server-generate-certs
cp %{_sourcedir}/scripts/epp-server-cli %{buildroot}/usr/bin/epp-server

# Copy systemd service
cp %{_sourcedir}/systemd/epp-server.service %{buildroot}/usr/lib/systemd/system/
cp %{_sourcedir}/systemd/oracle.conf %{buildroot}/etc/systemd/system/epp-server.service.d/

%files
%dir /opt/epp-server
/opt/epp-server/src
/opt/epp-server/venv
%config(noreplace) /etc/epp-server/epp.yaml
%config(noreplace) /etc/epp-server/logging.yaml
%dir /etc/epp-server/tls
%dir /etc/systemd/system/epp-server.service.d
%config(noreplace) %attr(600,root,root) /etc/systemd/system/epp-server.service.d/oracle.conf
%dir /var/log/registryd
%attr(755,root,root) /usr/bin/epp-server
%attr(755,root,root) /usr/bin/epp-server-generate-certs
/usr/lib/systemd/system/epp-server.service

%pre
# Create epp user if not exists
getent group epp >/dev/null || groupadd -r epp
getent passwd epp >/dev/null || useradd -r -g epp -d /opt/epp-server -s /sbin/nologin -c "EPP Server" epp

%post
# Fix permissions
chown -R epp:epp /opt/epp-server
chown -R epp:epp /etc/epp-server
chown -R epp:epp /var/log/registryd
chmod 600 /etc/epp-server/epp.yaml

# Reload systemd
systemctl daemon-reload

echo ""
echo "=========================================="
echo "EPP Server installed successfully!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Generate TLS certificates:"
echo "   epp-server-generate-certs"
echo ""
echo "2. Configure Oracle database:"
echo "   vi /etc/epp-server/epp.yaml"
echo ""
echo "3. Start the server:"
echo "   systemctl start epp-server"
echo "   systemctl enable epp-server"
echo ""

%preun
# Stop service before uninstall
if [ $1 -eq 0 ]; then
    systemctl stop epp-server >/dev/null 2>&1 || true
    systemctl disable epp-server >/dev/null 2>&1 || true
fi

%postun
# Reload systemd after uninstall
systemctl daemon-reload

%changelog
* Mon Jan 20 2025 AE Registry <support@aeda.ae> - 1.0.0-1
- Initial RPM release
- Full EPP RFC 5730-5734 support
- Oracle database integration
- TLS 1.2+ with client certificate authentication
