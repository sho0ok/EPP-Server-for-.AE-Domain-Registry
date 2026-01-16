# EPP Server Installation Guide

## Package Location

The self-contained installation package is located at:
```
/home/alhammadi/Downloads/ARI/epp-server/dist/epp-server-1.0.0.tar.gz
```

This package includes ALL Python dependencies bundled - no internet connection required on the target server.

---

## Prerequisites

### Target Server Requirements

| Requirement | Minimum Version | Notes |
|-------------|-----------------|-------|
| OS | RHEL/Rocky/Alma 9+ | Or compatible Linux |
| Python | 3.9+ | Usually pre-installed on RHEL 9 |
| Oracle Instant Client | 21+ | For database connectivity |
| OpenSSL | 1.1.1+ | For TLS support |
| Disk Space | 100MB | For application |
| RAM | 512MB | Minimum recommended |

### Install Oracle Instant Client (if not already installed)

```bash
# Download from Oracle or use dnf if configured
dnf install oracle-instantclient-basic

# Or download manually from:
# https://www.oracle.com/database/technologies/instant-client/linux-x86-64-downloads.html
```

---

## Installation Steps

### Step 1: Copy Package to Server

```bash
# From your local machine
scp /home/alhammadi/Downloads/ARI/epp-server/dist/epp-server-1.0.0.tar.gz user@your-server:/tmp/
```

### Step 2: Extract Package

```bash
# On the server
cd /tmp
tar -xzf epp-server-1.0.0.tar.gz
cd epp-server-1.0.0
```

### Step 3: Run Installation Script

```bash
# Must run as root
sudo ./install.sh
```

This will:
- Create `epp` user and group
- Install files to `/opt/epp-server/`
- Install systemd service
- Set proper permissions

### Step 4: Configure Oracle Connection

Edit the configuration file:
```bash
sudo vi /opt/epp-server/config/epp.yaml
```

Update the Oracle section:
```yaml
oracle:
  user: your_epp_user          # Database username
  dsn: "oracle-host:1521/AEREGSVC"  # Your Oracle connection string
  pool_min: 5
  pool_max: 20
  pool_increment: 2
```

### Step 5: Set Oracle Password

Choose one of these methods:

**Method A: Environment File (Recommended for Production)**
```bash
sudo mkdir -p /etc/systemd/system/epp-server.service.d
sudo cat > /etc/systemd/system/epp-server.service.d/oracle.conf << 'EOF'
[Service]
Environment="ORACLE_PASSWORD=your_secure_password_here"
EOF
sudo chmod 600 /etc/systemd/system/epp-server.service.d/oracle.conf
sudo systemctl daemon-reload
```

**Method B: Export Variable (For Testing)**
```bash
export ORACLE_PASSWORD='your_password'
```

### Step 6: Generate TLS Certificates

**Option A: Generate Self-Signed Certificates (Testing/Development)**
```bash
sudo /opt/epp-server/scripts/generate_certs.sh
```

This creates:
- `/opt/epp-server/config/tls/ca.crt` - CA certificate
- `/opt/epp-server/config/tls/server.crt` - Server certificate
- `/opt/epp-server/config/tls/server.key` - Server private key
- `/opt/epp-server/config/tls/client.crt` - Sample client certificate

**Option B: Use Your Own Certificates (Production)**
```bash
# Copy your certificates
sudo cp /path/to/your/server.crt /opt/epp-server/config/tls/
sudo cp /path/to/your/server.key /opt/epp-server/config/tls/
sudo cp /path/to/your/ca-bundle.crt /opt/epp-server/config/tls/

# Set permissions
sudo chown epp:epp /opt/epp-server/config/tls/*
sudo chmod 600 /opt/epp-server/config/tls/*.key
sudo chmod 644 /opt/epp-server/config/tls/*.crt
```

### Step 7: Start the Service

```bash
# Enable service to start on boot
sudo systemctl enable epp-server

# Start the service
sudo systemctl start epp-server

# Check status
sudo systemctl status epp-server
```

---

## Verification

### Check Service Status
```bash
sudo systemctl status epp-server
```

Expected output:
```
● epp-server.service - EPP Server for .AE Domain Registry
     Loaded: loaded (/etc/systemd/system/epp-server.service; enabled)
     Active: active (running) since ...
```

### Check Logs
```bash
# Real-time logs
sudo journalctl -u epp-server -f

# Recent logs
sudo journalctl -u epp-server -n 100
```

### Test TLS Connection
```bash
# Test with openssl (should show certificate info)
openssl s_client -connect localhost:700 -showcerts
```

### Test EPP Connection (with client certificate)
```bash
openssl s_client -connect localhost:700 \
    -cert /opt/epp-server/config/tls/client.crt \
    -key /opt/epp-server/config/tls/client.key \
    -CAfile /opt/epp-server/config/tls/ca.crt
```

### Run Local Tests (Before Installation)
```bash
# On build machine, verify components work without database
cd /path/to/epp-server
source build/epp-server-1.0.0/venv/bin/activate  # or use system python with deps
python tests/test_local.py

# Expected: 8/8 tests passed
# Tests: Module imports, Frame handler, XML processor, Response builder,
#        Validators, Password utilities, Database models, TLS config
```

---

## Directory Structure After Installation

```
/opt/epp-server/
├── venv/                    # Python virtual environment (all deps included)
├── src/                     # Application source code
├── config/
│   ├── epp.yaml            # Main configuration ← EDIT THIS
│   ├── logging.yaml        # Logging configuration
│   └── tls/                # TLS certificates
│       ├── ca.crt
│       ├── ca-bundle.crt
│       ├── server.crt
│       ├── server.key
│       ├── client.crt      # Sample client cert
│       └── client.key
├── logs/                    # Log files
├── run/                     # PID files
└── scripts/
    └── generate_certs.sh   # Certificate generator

/etc/systemd/system/
└── epp-server.service      # Systemd service file

/usr/bin/
└── epp-server              # Command wrapper script
```

---

## Configuration Reference

### /opt/epp-server/config/epp.yaml

```yaml
server:
  host: 0.0.0.0              # Listen on all interfaces
  port: 700                  # EPP standard port
  max_connections: 100       # Max concurrent connections
  connection_timeout: 300    # Connection timeout (seconds)
  read_timeout: 60           # Read timeout (seconds)
  server_name: "epp.aeda.ae" # Server hostname for greeting

tls:
  cert_file: /opt/epp-server/config/tls/server.crt
  key_file: /opt/epp-server/config/tls/server.key
  ca_file: /opt/epp-server/config/tls/ca-bundle.crt
  min_version: TLSv1.2       # Minimum TLS version
  verify_client: true        # Require client certificates

oracle:
  user: epp_user             # ← Change to your DB user
  dsn: "host:1521/service"   # ← Change to your Oracle DSN
  pool_min: 5
  pool_max: 20
  pool_increment: 2

epp:
  server_id: "TDRA .AE EPP Server"
  roid_suffix: "AE"
  supported_versions:
    - "1.0"
  supported_languages:
    - "en"
```

---

## Firewall Configuration

If firewall is enabled, allow EPP port:

```bash
# For firewalld
sudo firewall-cmd --permanent --add-port=700/tcp
sudo firewall-cmd --reload

# For iptables
sudo iptables -A INPUT -p tcp --dport 700 -j ACCEPT
```

---

## Common Operations

### Restart Service
```bash
sudo systemctl restart epp-server
```

### Stop Service
```bash
sudo systemctl stop epp-server
```

### View Logs
```bash
# Systemd journal
sudo journalctl -u epp-server -f

# Application logs
sudo tail -f /opt/epp-server/logs/epp.log
```

### Check Configuration
```bash
# Validate YAML syntax
/opt/epp-server/venv/bin/python -c "import yaml; yaml.safe_load(open('/opt/epp-server/config/epp.yaml'))" && echo "Config OK"
```

### Test Database Connection
```bash
export ORACLE_PASSWORD='your_password'
/opt/epp-server/venv/bin/python -c "
import oracledb
import os
conn = oracledb.connect(
    user='epp_user',
    password=os.environ['ORACLE_PASSWORD'],
    dsn='your-host:1521/AEREGSVC'
)
print('Database connection successful!')
conn.close()
"
```

---

## Troubleshooting

### Service Won't Start

1. **Check logs:**
   ```bash
   sudo journalctl -u epp-server -n 50 --no-pager
   ```

2. **Check Oracle connection:**
   - Verify Oracle Instant Client is installed
   - Verify DSN is correct
   - Verify password is set

3. **Check permissions:**
   ```bash
   ls -la /opt/epp-server/config/tls/
   # Keys should be 600, certs should be 644
   ```

### TLS Errors

1. **Certificate not found:**
   ```bash
   ls -la /opt/epp-server/config/tls/
   ```

2. **Permission denied:**
   ```bash
   sudo chown epp:epp /opt/epp-server/config/tls/*
   sudo chmod 600 /opt/epp-server/config/tls/*.key
   ```

### Oracle Connection Errors

1. **ORA-12541: No listener:**
   - Check Oracle host and port in DSN
   - Verify Oracle listener is running

2. **ORA-01017: Invalid username/password:**
   - Verify ORACLE_PASSWORD is set correctly
   - Verify username in epp.yaml

3. **Cannot locate Oracle Client library:**
   ```bash
   # Install Oracle Instant Client
   dnf install oracle-instantclient-basic

   # Or set LD_LIBRARY_PATH manually
   export LD_LIBRARY_PATH=/usr/lib/oracle/21/client64/lib
   ```

---

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop epp-server
sudo systemctl disable epp-server

# Remove files
sudo rm -rf /opt/epp-server
sudo rm /etc/systemd/system/epp-server.service
sudo rm -rf /etc/systemd/system/epp-server.service.d
sudo rm /usr/bin/epp-server

# Reload systemd
sudo systemctl daemon-reload

# Optionally remove user
sudo userdel epp
sudo groupdel epp
```

---

## Support

For issues or questions:
- Check logs: `journalctl -u epp-server -f`
- Review configuration: `/opt/epp-server/config/epp.yaml`
- See full documentation: `/opt/epp-server/README.md`

---

## Quick Reference Card

```
Package:     /home/alhammadi/Downloads/ARI/epp-server/dist/epp-server-1.0.0.tar.gz
Install:     tar -xzf epp-server-1.0.0.tar.gz && cd epp-server-1.0.0 && sudo ./install.sh
Config:      /opt/epp-server/config/epp.yaml
Certs:       /opt/epp-server/scripts/generate_certs.sh
Start:       sudo systemctl start epp-server
Stop:        sudo systemctl stop epp-server
Status:      sudo systemctl status epp-server
Logs:        sudo journalctl -u epp-server -f
Port:        700 (TCP)
```
