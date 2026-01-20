# EPP Server for .AE Domain Registry

A production-ready EPP (Extensible Provisioning Protocol) server for .AE domain registry. Implements RFC 5730-5734 with TLS 1.2+ and Oracle database backend.

## Requirements

- RHEL 9+ (Rocky Linux 9, AlmaLinux 9)
- Oracle Instant Client
- Oracle Database with registry schema
- Python 3.9 (included in RHEL 9)

## Installation

### Step 1: Build the RPM (on a machine with internet)

```bash
git clone https://github.com/sho0ok/EPP-Server-for-.AE-Domain-Registry.git
cd EPP-Server-for-.AE-Domain-Registry/build
./build-rpm.sh
```

This creates the RPM file at:
```
EPP-Server-for-.AE-Domain-Registry/dist/epp-server-1.0.0-1.el9.x86_64.rpm
```

### Step 2: Copy RPM to target server

```bash
scp dist/epp-server-1.0.0-1.el9.x86_64.rpm user@your-server:/tmp/
```

### Step 3: Install on target server (no internet required)

```bash
# SSH to your server
ssh user@your-server

# Install Oracle Instant Client (if not already installed)
yum install oracle-instantclient-basic

# Install EPP Server
yum install /tmp/epp-server-1.0.0-1.el9.x86_64.rpm
```

### Step 4: Generate TLS Certificates

```bash
epp-server-generate-certs
```

This creates certificates in `/etc/epp-server/tls/`.

### Step 5: Configure Database

Edit `/etc/epp-server/epp.yaml`:

```bash
vi /etc/epp-server/epp.yaml
```

Update the oracle section:
```yaml
oracle:
  user: your_db_user
  dsn: "your-oracle-host:1521/YOUR_SERVICE"
```

Set database password:

```bash
mkdir -p /etc/systemd/system/epp-server.service.d
cat > /etc/systemd/system/epp-server.service.d/oracle.conf << EOF
[Service]
Environment="EPP_ORACLE_PASSWORD=your_password"
EOF
chmod 600 /etc/systemd/system/epp-server.service.d/oracle.conf
systemctl daemon-reload
```

### Step 6: Start Server

```bash
systemctl start epp-server
systemctl enable epp-server
```

### Step 7: Verify

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
systemctl status epp-server     # Status
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

See [docs/](docs/) for detailed documentation.

## License

MIT License
