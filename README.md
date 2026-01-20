# EPP Server for .AE Domain Registry

A production-ready EPP (Extensible Provisioning Protocol) server for .AE domain registry. Implements RFC 5730-5734 with TLS 1.2+ and Oracle database backend.

## Requirements

- RHEL 9+ (Rocky Linux 9, AlmaLinux 9)
- Oracle Instant Client
- Oracle Database with registry schema
- Python 3.9 (included in RHEL 9)

## Installation

### Step 1: Download RPM

Download the latest RPM from [Releases](https://github.com/sho0ok/EPP-Server-for-.AE-Domain-Registry/releases).

### Step 2: Copy to server

```bash
scp epp-server-1.0.0-1.el9.x86_64.rpm user@your-server:/tmp/
```

### Step 3: Install (no internet required)

```bash
ssh user@your-server
yum install /tmp/epp-server-1.0.0-1.el9.x86_64.rpm
```

### Step 4: Generate TLS Certificates

```bash
cd /etc/epp-server/tls
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=EPP CA"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=epp.aeda.ae"
openssl x509 -req -days 3650 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
rm server.csr
chmod 600 *.key
```

### Step 5: Configure Database

Edit `/etc/epp-server/epp.yaml`:
```yaml
oracle:
  user: your_db_user                          # Oracle username
  dsn: "192.168.1.100:1521/AEREGSVC"          # host:port/service_name
```

Set password:
```bash
vi /etc/systemd/system/epp-server.service.d/oracle.conf
```
Change `CHANGE_ME` to your Oracle password, then:
```bash
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
