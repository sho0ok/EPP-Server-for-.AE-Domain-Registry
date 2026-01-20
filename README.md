# EPP Server for .AE Domain Registry

A production-ready EPP (Extensible Provisioning Protocol) server for .AE domain registry. Implements RFC 5730-5734 with TLS 1.2+ and Oracle database backend.

## Requirements

- RHEL 9+ (Rocky Linux 9, AlmaLinux 9)
- Oracle Instant Client
- Oracle Database with registry schema

## Installation

### 1. Install Oracle Instant Client

```bash
dnf install oracle-instantclient-release-el9
dnf install oracle-instantclient-basic
```

### 2. Install EPP Server

Download from [Releases](https://github.com/sho0ok/EPP-Server-for-.AE-Domain-Registry/releases):

```bash
dnf install ./epp-server-1.0.0-1.el9.x86_64.rpm
```

### 3. Generate Certificates

```bash
epp-server-generate-certs
```

### 4. Configure Database

Edit `/etc/epp-server/epp.yaml`:

```yaml
oracle:
  user: your_db_user
  dsn: "your-oracle-host:1521/YOUR_SERVICE"
```

Set password:

```bash
mkdir -p /etc/systemd/system/epp-server.service.d
cat > /etc/systemd/system/epp-server.service.d/oracle.conf << EOF
[Service]
Environment="EPP_ORACLE_PASSWORD=your_password"
EOF
chmod 600 /etc/systemd/system/epp-server.service.d/oracle.conf
systemctl daemon-reload
```

### 5. Start Server

```bash
systemctl start epp-server
systemctl enable epp-server
```

### 6. Verify

```bash
systemctl status epp-server
openssl s_client -connect localhost:700
```

## Configuration Files

| File | Description |
|------|-------------|
| `/etc/epp-server/epp.yaml` | Main configuration |
| `/etc/epp-server/logging.yaml` | Logging settings |
| `/etc/epp-server/tls/` | TLS certificates |

## Commands

```bash
systemctl start epp-server      # Start
systemctl stop epp-server       # Stop
systemctl restart epp-server    # Restart
journalctl -u epp-server -f     # View logs
```

## Firewall

```bash
firewall-cmd --permanent --add-port=700/tcp
firewall-cmd --reload
```

## EPP Client

For registrar client toolkit: [EPP Client Toolkit](https://github.com/sho0ok/EPP-Client-Toolkit-for-.AE-Domain-Registry)

## Documentation

See [docs/](docs/) for detailed documentation:
- [Development Setup](docs/GETTING_STARTED.md)
- [Detailed Installation Options](docs/INSTALL.md)

## License

MIT License
