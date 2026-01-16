# EPP Server for .AE Domain Registry

A complete EPP (Extensible Provisioning Protocol) server implementation for the .AE domain registry, compliant with RFC 5730-5734.

## Features

- **Full RFC Compliance**: Implements RFC 5730 (EPP), RFC 5731 (Domain), RFC 5732 (Host), RFC 5733 (Contact), RFC 5734 (TCP Transport)
- **Secure by Design**: TLS 1.2+ with client certificate authentication
- **Oracle Backend**: Direct integration with ARI Oracle schema
- **Complete Operations**: Domain/Contact/Host CRUD, transfers, renewals
- **Transaction Logging**: All operations logged to CONNECTIONS, SESSIONS, TRANSACTIONS tables
- **Self-Contained RPM**: All Python dependencies bundled - no internet needed for deployment

## System Requirements

### Target Server
- RedHat/Rocky/Alma Linux 9+
- Oracle Instant Client 21+
- Python 3.9+ (included in RHEL 9)
- OpenSSL 1.1.1+

### Build Machine
- Python 3.9+
- pip and venv modules
- rpm-build package
- Development libraries: libxml2-devel, libxslt-devel, openssl-devel, gcc

## Quick Start

### Building the RPM

```bash
# Install build dependencies (RHEL/Rocky/Alma)
dnf install python3 python3-pip python3-devel rpm-build \
    gcc libxml2-devel libxslt-devel openssl-devel

# Build the RPM
cd /path/to/epp-server
./packaging/build_rpm.sh

# RPM will be created in packaging/epp-server-1.0.0-1.el9.x86_64.rpm
```

### Installation

```bash
# Install Oracle Instant Client (if not already installed)
dnf install oracle-instantclient-basic

# Install EPP Server
dnf install ./epp-server-1.0.0-1.el9.x86_64.rpm
```

### Configuration

#### 1. Configure Oracle Connection

Edit `/opt/epp-server/config/epp.yaml`:

```yaml
oracle:
  user: epp_user
  dsn: "oracle-host:1521/AEREGSVC"
  pool_min: 5
  pool_max: 20
```

Set Oracle password (choose one method):

```bash
# Method 1: Environment variable
export ORACLE_PASSWORD='your_secure_password'

# Method 2: Systemd override
mkdir -p /etc/systemd/system/epp-server.service.d
cat > /etc/systemd/system/epp-server.service.d/oracle.conf << EOF
[Service]
Environment="ORACLE_PASSWORD=your_secure_password"
EOF
systemctl daemon-reload
```

#### 2. Generate TLS Certificates

```bash
# Generate self-signed certificates (for testing)
/opt/epp-server/scripts/generate_certs.sh

# For production, use certificates from your organization's CA
# and place them in /opt/epp-server/config/tls/
```

#### 3. Start the Service

```bash
# Enable and start
systemctl enable epp-server
systemctl start epp-server

# Check status
systemctl status epp-server

# View logs
journalctl -u epp-server -f
```

## Directory Structure

```
/opt/epp-server/
├── venv/                    # Bundled Python virtual environment
│   └── lib/python3.x/site-packages/
│       ├── oracledb/        # Oracle database driver
│       ├── lxml/            # XML processing
│       ├── yaml/            # Configuration parsing
│       ├── cryptography/    # TLS and security
│       └── dateutil/        # Date calculations
├── src/
│   ├── server.py            # Main server entry point
│   ├── commands/            # EPP command handlers
│   │   ├── domain.py        # domain:check/info/create/update/delete/renew/transfer
│   │   ├── contact.py       # contact:check/info/create/update/delete
│   │   ├── host.py          # host:check/info/create/update/delete
│   │   └── session.py       # login/logout/hello/poll
│   ├── core/
│   │   ├── tls_handler.py   # TLS connection handling
│   │   ├── frame_handler.py # EPP framing (4-byte length prefix)
│   │   ├── xml_processor.py # XML parsing
│   │   └── session_manager.py
│   ├── database/
│   │   ├── connection.py    # Oracle connection pool
│   │   ├── models.py        # Data models
│   │   └── repositories/    # Database operations
│   ├── utils/
│   │   ├── response_builder.py
│   │   ├── roid_generator.py
│   │   └── password_utils.py
│   └── validators/
│       └── epp_validator.py
├── config/
│   ├── epp.yaml             # Server configuration
│   ├── logging.yaml         # Logging configuration
│   └── tls/                 # TLS certificates
├── logs/                    # Log files
└── scripts/
    └── generate_certs.sh    # Certificate generator
```

## Configuration Reference

### epp.yaml

```yaml
server:
  host: 0.0.0.0              # Listen address
  port: 700                  # EPP standard port
  max_connections: 100       # Maximum concurrent connections
  connection_timeout: 300    # Connection timeout (seconds)
  read_timeout: 60           # Read timeout (seconds)
  server_name: "epp.aeda.ae" # Server hostname

tls:
  cert_file: /opt/epp-server/config/tls/server.crt
  key_file: /opt/epp-server/config/tls/server.key
  ca_file: /opt/epp-server/config/tls/ca-bundle.crt
  min_version: TLSv1.2       # Minimum TLS version
  verify_client: true        # Require client certificate

oracle:
  user: epp_user             # Database username
  dsn: "host:1521/service"   # Oracle connection string
  pool_min: 5                # Minimum pool connections
  pool_max: 20               # Maximum pool connections
  pool_increment: 2          # Pool growth increment

epp:
  server_id: "TDRA .AE EPP Server"
  roid_suffix: "AE"          # ROID suffix (e.g., 12345-AE)
  supported_versions:
    - "1.0"
  supported_languages:
    - "en"
  supported_objects:
    - "urn:ietf:params:xml:ns:domain-1.0"
    - "urn:ietf:params:xml:ns:contact-1.0"
    - "urn:ietf:params:xml:ns:host-1.0"
```

## EPP Commands Supported

### Session Commands
- `hello` - Server greeting
- `login` - Authenticate session
- `logout` - End session
- `poll` - Retrieve/acknowledge messages

### Domain Commands
- `domain:check` - Check availability
- `domain:info` - Get domain details
- `domain:create` - Register domain
- `domain:update` - Modify domain
- `domain:delete` - Delete domain
- `domain:renew` - Extend registration
- `domain:transfer` - Transfer domain (request/approve/reject/cancel/query)

### Contact Commands
- `contact:check` - Check availability
- `contact:info` - Get contact details
- `contact:create` - Create contact
- `contact:update` - Modify contact
- `contact:delete` - Delete contact

### Host Commands
- `host:check` - Check availability
- `host:info` - Get host details
- `host:create` - Create nameserver
- `host:update` - Modify nameserver
- `host:delete` - Delete nameserver

## Security

### TLS Configuration
- Minimum TLS 1.2 (TLS 1.3 supported)
- Client certificate required for authentication
- Certificate CN used as registrar identifier

### Authentication Flow
1. Client connects with TLS certificate
2. Server extracts CN from certificate
3. Client sends EPP login with username/password
4. Server validates credentials against USERS table
5. Server verifies client IP against ACCOUNT_EPP_ADDRESSES whitelist

### Database Security
- All queries use parameterized statements (SQL injection safe)
- Passwords verified with timing-safe comparison
- Auth info can be hashed for storage

## Monitoring

### Logs
```bash
# Real-time logs
journalctl -u epp-server -f

# Application logs
tail -f /opt/epp-server/logs/epp.log
```

### Service Status
```bash
systemctl status epp-server
```

### Database Monitoring
```sql
-- Active connections
SELECT * FROM CONNECTIONS WHERE CNN_END_TIME IS NULL;

-- Recent transactions
SELECT * FROM TRANSACTIONS ORDER BY TRN_ID DESC FETCH FIRST 100 ROWS ONLY;

-- Session statistics
SELECT * FROM SESSIONS WHERE SES_END_TIME IS NULL;
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
journalctl -u epp-server -n 50

# Verify Oracle connection
export ORACLE_PASSWORD='password'
/opt/epp-server/venv/bin/python -c "
import oracledb
conn = oracledb.connect(user='epp_user', password='$ORACLE_PASSWORD', dsn='host:1521/service')
print('Connected successfully')
conn.close()
"
```

### TLS Certificate Issues

```bash
# Verify certificate
openssl x509 -in /opt/epp-server/config/tls/server.crt -text -noout

# Test TLS connection
openssl s_client -connect localhost:700 \
    -cert client.crt -key client.key -CAfile ca.crt
```

### Permission Issues

```bash
# Fix ownership
chown -R epp:epp /opt/epp-server/logs
chown -R epp:epp /opt/epp-server/run
chmod 750 /opt/epp-server/config/tls
chmod 600 /opt/epp-server/config/tls/*.key
```

## Development

### Running Locally

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set Oracle password
export ORACLE_PASSWORD='your_password'

# Run server
python -m src.server --config config/epp.yaml
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest tests/
```

## License

Proprietary - AEDA/TDRA

## Support

For support, contact the EPP Server Team at epp@aeda.ae
