# EPP Client Manual Testing Guide

This guide shows how to test all EPP commands manually using both the CLI tool and Python API.

## Prerequisites

### 1. Start the Mock Server

```bash
cd /home/alhammadi/Downloads/ARI/epp-client
python3 tests/mock_server.py &
```

The server runs on `localhost:7700`.

### 2. Set Up Environment

```bash
cd /home/alhammadi/Downloads/ARI/epp-client
source venv/bin/activate
```

### 3. Certificate Paths

```
CA:     /home/alhammadi/Downloads/ARI/test-certs/ca.crt
Cert:   /home/alhammadi/Downloads/ARI/test-certs/client.crt
Key:    /home/alhammadi/Downloads/ARI/test-certs/client.key
```

---

## CLI Commands

### Base Command

All CLI commands use this base:

```bash
epp --host localhost --port 7700 \
    --cert /home/alhammadi/Downloads/ARI/test-certs/client.crt \
    --key /home/alhammadi/Downloads/ARI/test-certs/client.key \
    --ca /home/alhammadi/Downloads/ARI/test-certs/ca.crt \
    -u testregistrar -P testpass
```

For convenience, create an alias:

```bash
alias epptest='epp --host localhost --port 7700 --cert /home/alhammadi/Downloads/ARI/test-certs/client.crt --key /home/alhammadi/Downloads/ARI/test-certs/client.key --ca /home/alhammadi/Downloads/ARI/test-certs/ca.crt -u testregistrar -P testpass'
```

---

## Session Commands

### Hello (Get Server Greeting)

```bash
epptest hello
```

---

## Domain Commands

### Check Domain Availability

```bash
# ASCII domains
epptest domain check example.ae test.ae mydomain.ae

# IDN Arabic domains
epptest domain check مثال.امارات تجربة.امارات

# JSON output
epptest --format json domain check example.ae
```

### Get Domain Info

```bash
# ASCII
epptest domain info example.ae

# IDN
epptest domain info مثال.امارات

# With auth info
epptest domain info example.ae --auth-info secret123
```

### Create Domain

```bash
# Basic create
epptest domain create newdomain.ae --registrant REG001

# Full create with all options
epptest domain create newdomain.ae \
    --registrant REG001 \
    --admin ADM001 \
    --tech TCH001 \
    --ns ns1.example.ae \
    --ns ns2.example.ae \
    --period 2

# IDN domain
epptest domain create نطاق.امارات --registrant REG001
```

### Update Domain

```bash
# Add nameserver
epptest domain update example.ae --add-ns ns3.example.ae

# Remove nameserver
epptest domain update example.ae --rem-ns ns1.example.ae

# Change registrant
epptest domain update example.ae --registrant NEWREG001

# Add status
epptest domain update example.ae --add-status clientHold

# Add status with reason/comment
epptest domain update example.ae --add-status clientHold --add-status-reason "Payment pending"

# Multiple statuses with reasons
epptest domain update example.ae \
    --add-status clientHold --add-status-reason "Under investigation" \
    --add-status clientTransferProhibited --add-status-reason "Legal dispute"

# Remove status
epptest domain update example.ae --rem-status clientHold

# Add multiple statuses (without reasons)
epptest domain update example.ae --add-status clientHold --add-status clientTransferProhibited
```

#### Available Client Statuses

Registrars can set these client-side statuses:

| Status | Description |
|--------|-------------|
| `clientHold` | Prevents domain from resolving in DNS |
| `clientTransferProhibited` | Prevents domain transfers |
| `clientUpdateProhibited` | Prevents domain updates |
| `clientDeleteProhibited` | Prevents domain deletion |
| `clientRenewProhibited` | Prevents domain renewal |

#### Status Reasons

You can add a reason/comment when setting a status. This is useful for tracking why a hold was placed:

```bash
# Common reasons
epptest domain update example.ae --add-status clientHold --add-status-reason "Payment pending"
epptest domain update example.ae --add-status clientHold --add-status-reason "Under investigation"
epptest domain update example.ae --add-status clientHold --add-status-reason "Trademark dispute"
epptest domain update example.ae --add-status clientHold --add-status-reason "Account suspended"

# Arabic reason
epptest domain update مثال.امارات --add-status clientHold --add-status-reason "قيد التحقيق"
```

### Renew Domain

```bash
# Renew for 1 year
epptest domain renew example.ae --exp-date 2025-01-01

# Renew for 2 years
epptest domain renew example.ae --exp-date 2025-01-01 --period 2
```

### Delete Domain

```bash
# With confirmation prompt
epptest domain delete example.ae

# Skip confirmation
epptest domain delete example.ae -y
```

### Transfer Domain

```bash
# Request transfer
epptest domain transfer example.ae request --auth-info secret123

# Query transfer status
epptest domain transfer example.ae query

# Approve transfer (as losing registrar)
epptest domain transfer example.ae approve

# Reject transfer (as losing registrar)
epptest domain transfer example.ae reject

# Cancel transfer (as gaining registrar)
epptest domain transfer example.ae cancel
```

---

## Contact Commands

### Check Contact Availability

```bash
# ASCII IDs
epptest contact check contact1 contact2 contact3

# Arabic IDs
epptest contact check جهة1 جهة2
```

### Get Contact Info

```bash
epptest contact info CONTACT001

# With auth info
epptest contact info CONTACT001 --auth-info secret123
```

### Create Contact

```bash
# Basic create
epptest contact create NEWCONTACT \
    --name "John Doe" \
    --email john@example.ae \
    --city Dubai \
    --country AE

# Full create
epptest contact create NEWCONTACT \
    --name "John Doe" \
    --org "Example Company" \
    --email john@example.ae \
    --street "123 Main Street" \
    --street "Suite 100" \
    --city Dubai \
    --state Dubai \
    --postal-code 00000 \
    --country AE \
    --voice +971.41234567 \
    --fax +971.41234568

# Arabic contact
epptest contact create جهة001 \
    --name "محمد أحمد" \
    --email test@example.ae \
    --city دبي \
    --country AE
```

### Update Contact

```bash
# Update email
epptest contact update CONTACT001 --email newemail@example.ae

# Update phone
epptest contact update CONTACT001 --voice +971.49876543

# Update multiple fields
epptest contact update CONTACT001 \
    --email newemail@example.ae \
    --voice +971.49876543 \
    --fax +971.49876544
```

### Delete Contact

```bash
# With confirmation
epptest contact delete CONTACT001

# Skip confirmation
epptest contact delete CONTACT001 -y
```

---

## Host Commands

### Check Host Availability

```bash
# ASCII
epptest host check ns1.example.ae ns2.example.ae

# IDN
epptest host check ns1.مثال.امارات ns2.مثال.امارات
```

### Get Host Info

```bash
epptest host info ns1.example.ae
```

### Create Host

```bash
# With IPv4
epptest host create ns1.newdomain.ae --ipv4 192.0.2.1

# With IPv4 and IPv6
epptest host create ns1.newdomain.ae \
    --ipv4 192.0.2.1 \
    --ipv6 2001:db8::1

# Multiple IPs
epptest host create ns1.newdomain.ae \
    --ipv4 192.0.2.1 \
    --ipv4 192.0.2.2 \
    --ipv6 2001:db8::1

# IDN host
epptest host create ns1.نطاق.امارات --ipv4 192.0.2.10
```

### Update Host

```bash
# Add IP
epptest host update ns1.example.ae --add-ipv4 192.0.2.2

# Remove IP
epptest host update ns1.example.ae --rem-ipv4 192.0.2.1

# Add IPv6
epptest host update ns1.example.ae --add-ipv6 2001:db8::2

# Rename host
epptest host update ns1.example.ae --new-name ns1.newname.ae
```

### Delete Host

```bash
# With confirmation
epptest host delete ns1.example.ae

# Skip confirmation
epptest host delete ns1.example.ae -y
```

---

## Poll Commands

### Request Poll Message

```bash
epptest poll request
```

### Acknowledge Poll Message

```bash
epptest poll ack MSG12345
```

---

## Output Formats

### Table (Default)

```bash
epptest domain check example.ae
```

### JSON

```bash
epptest --format json domain check example.ae
```

### XML

```bash
epptest --format xml domain check example.ae
```

---

## Python API Examples

### Basic Usage

```python
from epp_client import EPPClient

client = EPPClient(
    host="localhost",
    port=7700,
    cert_file="/home/alhammadi/Downloads/ARI/test-certs/client.crt",
    key_file="/home/alhammadi/Downloads/ARI/test-certs/client.key",
    ca_file="/home/alhammadi/Downloads/ARI/test-certs/ca.crt",
)

# Connect and login
client.connect()
client.login("testregistrar", "testpassword")

# Check domains
result = client.domain_check(["example.ae", "مثال.امارات"])
for item in result.results:
    print(f"{item.name}: {'Available' if item.available else 'Taken'}")

# Create domain
result = client.domain_create(
    name="newdomain.ae",
    registrant="REG001",
    admin="ADM001",
    tech="TCH001",
    nameservers=["ns1.example.ae", "ns2.example.ae"],
    period=1,
)
print(f"Created: {result.name}, Expires: {result.ex_date}")

# Logout and disconnect
client.logout()
client.disconnect()
```

### Using Context Manager

```python
from epp_client import EPPClient

with EPPClient(
    host="localhost",
    port=7700,
    cert_file="/home/alhammadi/Downloads/ARI/test-certs/client.crt",
    key_file="/home/alhammadi/Downloads/ARI/test-certs/client.key",
    ca_file="/home/alhammadi/Downloads/ARI/test-certs/ca.crt",
) as client:
    client.login("testregistrar", "testpassword")

    # Your operations here
    result = client.domain_check(["example.ae"])

    client.logout()
```

### Async Client

```python
import asyncio
from epp_client import AsyncEPPClient

async def main():
    async with AsyncEPPClient(
        host="localhost",
        port=7700,
        cert_file="/home/alhammadi/Downloads/ARI/test-certs/client.crt",
        key_file="/home/alhammadi/Downloads/ARI/test-certs/client.key",
        ca_file="/home/alhammadi/Downloads/ARI/test-certs/ca.crt",
    ) as client:
        await client.login("testregistrar", "testpassword")

        result = await client.domain_check(["example.ae"])
        print(result.results)

        await client.logout()

asyncio.run(main())
```

### Full Domain Lifecycle

```python
from epp_client import EPPClient

client = EPPClient(
    host="localhost",
    port=7700,
    cert_file="/home/alhammadi/Downloads/ARI/test-certs/client.crt",
    key_file="/home/alhammadi/Downloads/ARI/test-certs/client.key",
    ca_file="/home/alhammadi/Downloads/ARI/test-certs/ca.crt",
)

try:
    client.connect()
    client.login("testregistrar", "testpassword")

    # 1. Check availability
    print("=== Check ===")
    result = client.domain_check(["lifecycle-test.ae"])
    print(f"Available: {result.results[0].available}")

    # 2. Create
    print("\n=== Create ===")
    result = client.domain_create(
        name="lifecycle-test.ae",
        registrant="REG001",
        admin="ADM001",
        tech="TCH001",
    )
    print(f"Created: {result.name}")
    print(f"Expires: {result.ex_date}")

    # 3. Info
    print("\n=== Info ===")
    info = client.domain_info("lifecycle-test.ae")
    print(f"Name: {info.name}")
    print(f"Status: {info.status}")
    print(f"Registrant: {info.registrant}")

    # 4. Update - add nameserver
    print("\n=== Update (add nameserver) ===")
    response = client.domain_update(
        name="lifecycle-test.ae",
        add_ns=["ns3.example.ae"],
    )
    print(f"Update: {response.code} - {response.message}")

    # 4b. Update - add clientHold status (simple)
    print("\n=== Update (add clientHold) ===")
    response = client.domain_update(
        name="lifecycle-test.ae",
        add_status=["clientHold"],
    )
    print(f"Update: {response.code} - {response.message}")

    # 4c. Update - add clientHold with reason
    from epp_client import StatusValue
    print("\n=== Update (add clientHold with reason) ===")
    response = client.domain_update(
        name="lifecycle-test.ae",
        add_status=[StatusValue("clientHold", "Payment pending")],
    )
    print(f"Update: {response.code} - {response.message}")

    # 4d. Update - remove clientHold status
    print("\n=== Update (remove clientHold) ===")
    response = client.domain_update(
        name="lifecycle-test.ae",
        rem_status=["clientHold"],
    )
    print(f"Update: {response.code} - {response.message}")

    # 5. Renew
    print("\n=== Renew ===")
    result = client.domain_renew(
        name="lifecycle-test.ae",
        cur_exp_date="2027-01-17",
        period=1,
    )
    print(f"New Expiry: {result.ex_date}")

    # 6. Delete
    print("\n=== Delete ===")
    response = client.domain_delete("lifecycle-test.ae")
    print(f"Delete: {response.code} - {response.message}")

    client.logout()

finally:
    client.disconnect()
```

### Contact Operations

```python
from epp_client import EPPClient

client = EPPClient(
    host="localhost",
    port=7700,
    cert_file="/home/alhammadi/Downloads/ARI/test-certs/client.crt",
    key_file="/home/alhammadi/Downloads/ARI/test-certs/client.key",
    ca_file="/home/alhammadi/Downloads/ARI/test-certs/ca.crt",
)

try:
    client.connect()
    client.login("testregistrar", "testpassword")

    # Create contact
    result = client.contact_create(
        id="TESTCONTACT",
        name="Test User",
        email="test@example.ae",
        city="Dubai",
        country_code="AE",
        org="Test Organization",
        street=["123 Test Street"],
        voice="+971.41234567",
    )
    print(f"Contact created: {result.id}")

    # Get info
    info = client.contact_info("TESTCONTACT")
    print(f"Email: {info.email}")
    print(f"Voice: {info.voice}")

    # Update
    client.contact_update(
        id="TESTCONTACT",
        new_email="updated@example.ae",
    )
    print("Contact updated")

    # Delete
    client.contact_delete("TESTCONTACT")
    print("Contact deleted")

    client.logout()

finally:
    client.disconnect()
```

### Host Operations

```python
from epp_client import EPPClient

client = EPPClient(
    host="localhost",
    port=7700,
    cert_file="/home/alhammadi/Downloads/ARI/test-certs/client.crt",
    key_file="/home/alhammadi/Downloads/ARI/test-certs/client.key",
    ca_file="/home/alhammadi/Downloads/ARI/test-certs/ca.crt",
)

try:
    client.connect()
    client.login("testregistrar", "testpassword")

    # Create host
    result = client.host_create(
        name="ns1.testdomain.ae",
        ipv4=["192.0.2.1", "192.0.2.2"],
        ipv6=["2001:db8::1"],
    )
    print(f"Host created: {result.name}")

    # Get info
    info = client.host_info("ns1.testdomain.ae")
    print(f"Status: {info.status}")
    for addr in info.addresses:
        print(f"  {addr.ip_version}: {addr.address}")

    # Update - add IP
    client.host_update(
        name="ns1.testdomain.ae",
        add_ipv4=["192.0.2.3"],
    )
    print("Host updated")

    # Delete
    client.host_delete("ns1.testdomain.ae")
    print("Host deleted")

    client.logout()

finally:
    client.disconnect()
```

### Transfer Operations

```python
from epp_client import EPPClient

client = EPPClient(
    host="localhost",
    port=7700,
    cert_file="/home/alhammadi/Downloads/ARI/test-certs/client.crt",
    key_file="/home/alhammadi/Downloads/ARI/test-certs/client.key",
    ca_file="/home/alhammadi/Downloads/ARI/test-certs/ca.crt",
)

try:
    client.connect()
    client.login("testregistrar", "testpassword")

    # Request transfer (as gaining registrar)
    result = client.domain_transfer_request(
        name="transfer-test.ae",
        auth_info="secret123",
    )
    print(f"Transfer requested: {result.name}")
    print(f"Status: {result.tr_status}")

    # Query transfer status
    result = client.domain_transfer_query("transfer-test.ae")
    print(f"Transfer status: {result.tr_status}")

    # Approve transfer (as losing registrar)
    client.domain_transfer_approve("transfer-test.ae")
    print("Transfer approved")

    # Or reject
    # client.domain_transfer_reject("transfer-test.ae")

    # Or cancel (as gaining registrar)
    # client.domain_transfer_cancel("transfer-test.ae")

    client.logout()

finally:
    client.disconnect()
```

---

## Stop Mock Server

```bash
pkill -f mock_server.py
```

---

## Troubleshooting

### Connection Refused

Make sure the mock server is running:

```bash
ps aux | grep mock_server
# If not running:
python3 tests/mock_server.py &
```

### Certificate Errors

Verify certificate paths exist:

```bash
ls -la /home/alhammadi/Downloads/ARI/test-certs/
```

### Import Errors

Make sure you're in the virtual environment:

```bash
source venv/bin/activate
```

### Command Not Found

Install the package:

```bash
cd /home/alhammadi/Downloads/ARI/epp-client
pip install -e .
```

---

## Real EPP Server Testing

This section covers testing against the actual .AE registry EPP server.

### Step 1: Obtain Registrar Credentials

Contact the registry to obtain:
- Registrar ID (client ID)
- Password
- OT&E (test) environment access

### Step 2: Generate Client Certificate

The registry requires mutual TLS authentication. Generate a certificate signing request (CSR):

```bash
# Create a directory for certificates
mkdir -p ~/epp-certs
cd ~/epp-certs

# Generate private key (2048-bit RSA)
openssl genrsa -out registrar.key 2048

# Generate CSR
openssl req -new -key registrar.key -out registrar.csr \
    -subj "/C=AE/ST=Dubai/L=Dubai/O=Your Company Name/CN=your-registrar-id"
```

### Step 3: Submit CSR to Registry

1. Log into the registry portal
2. Navigate to Certificate Management
3. Upload the `registrar.csr` file
4. Wait for approval (usually within 24-48 hours)
5. Download the signed certificate (`registrar.crt`)
6. Download the registry CA certificate (`registry-ca.crt`)

### Step 4: Verify Certificates

```bash
# Verify certificate matches key
openssl x509 -noout -modulus -in registrar.crt | openssl md5
openssl rsa -noout -modulus -in registrar.key | openssl md5
# Both should output the same MD5 hash

# View certificate details
openssl x509 -in registrar.crt -text -noout

# Verify certificate chain
openssl verify -CAfile registry-ca.crt registrar.crt
```

### Step 5: Copy Certificates to Server

If testing from a remote server:

```bash
# Create directory on server
ssh user@server "mkdir -p ~/epp-certs"

# Copy certificates
scp registrar.crt registrar.key registry-ca.crt user@server:~/epp-certs/

# Set proper permissions (private key should be readable only by owner)
ssh user@server "chmod 600 ~/epp-certs/registrar.key"
ssh user@server "chmod 644 ~/epp-certs/registrar.crt ~/epp-certs/registry-ca.crt"
```

### Step 6: Configure CLI

Create a config file at `~/.epp/config.yaml`:

```yaml
# OT&E (Test) Environment
profiles:
  ote:
    server:
      host: epp-ote.aeda.ae
      port: 700
      timeout: 30
      verify_server: true
    credentials:
      client_id: YOUR_REGISTRAR_ID
      # password: leave empty to prompt, or use EPP_PASSWORD env var
    certs:
      cert_file: ~/epp-certs/registrar.crt
      key_file: ~/epp-certs/registrar.key
      ca_file: ~/epp-certs/registry-ca.crt

  # Production Environment
  production:
    server:
      host: epp.aeda.ae
      port: 700
      timeout: 30
      verify_server: true
    credentials:
      client_id: YOUR_REGISTRAR_ID
    certs:
      cert_file: ~/epp-certs/registrar.crt
      key_file: ~/epp-certs/registrar.key
      ca_file: ~/epp-certs/registry-ca.crt

default_profile: ote
```

### Step 7: Test Connection

```bash
# Set password (or you'll be prompted)
export EPP_PASSWORD='your-password'

# Test with OT&E environment
epp --profile ote hello

# Expected output: Server greeting with version, languages, supported extensions
```

### Step 8: Run Read-Only Commands First

Always start with non-destructive commands:

```bash
# Check domain availability
epp --profile ote domain check test-domain-12345.ae

# Query existing domain info (use a domain you own)
epp --profile ote domain info your-domain.ae

# Check contact availability
epp --profile ote contact check testcontact123

# Check host availability
epp --profile ote host check ns1.your-domain.ae
```

### Step 9: Test Create Operations (OT&E Only)

Only in the OT&E environment:

```bash
# Create a test contact
epp --profile ote contact create TESTCONTACT001 \
    --name "Test User" \
    --email test@example.ae \
    --city Dubai \
    --country AE \
    --voice +971.41234567

# Create a test domain
epp --profile ote domain create test-domain-12345.ae \
    --registrant TESTCONTACT001

# For restricted zones (.co.ae, .gov.ae, etc.)
epp --profile ote domain create test-company.co.ae \
    --registrant TESTCONTACT001 \
    --eligibility-type TradeLicense \
    --eligibility-name "Test Company LLC" \
    --eligibility-id "123456" \
    --eligibility-id-type TradeLicense
```

### Step 10: Production Deployment

Once OT&E testing passes:

1. Request production credentials from registry
2. Update config with production server (`epp.aeda.ae`)
3. Start with read-only commands
4. Proceed with caution - production changes are real!

```bash
# Switch to production profile
epp --profile production domain check example.ae
```

---

## Python API for Production

```python
from epp_client import EPPClient, AEEligibility
import os

# Load password from environment
password = os.environ.get('EPP_PASSWORD')

client = EPPClient(
    host="epp-ote.aeda.ae",  # or epp.aeda.ae for production
    port=700,
    cert_file=os.path.expanduser("~/epp-certs/registrar.crt"),
    key_file=os.path.expanduser("~/epp-certs/registrar.key"),
    ca_file=os.path.expanduser("~/epp-certs/registry-ca.crt"),
    timeout=30,
    verify_server=True,
)

try:
    greeting = client.connect()
    print(f"Connected to: {greeting.server_id}")

    client.login("YOUR_REGISTRAR_ID", password)
    print("Logged in successfully")

    # Your operations here
    result = client.domain_check(["example.ae"])
    for item in result.results:
        status = "Available" if item.available else "Taken"
        print(f"{item.name}: {status}")

    client.logout()

finally:
    client.disconnect()
```

---

---

## EPP Server Setup (Registry Side)

If you're setting up the EPP server (registry side), follow these steps:

### Step 1: Database Setup

The EPP server requires an Oracle database. Configure the connection:

```bash
# Create environment file
cat > /path/to/epp-server/.env << 'EOF'
# Database Configuration
DB_HOST=your-oracle-host.example.com
DB_PORT=1521
DB_SERVICE=EPPDB
DB_USER=epp_user
DB_PASSWORD=your_secure_password

# Server Configuration
EPP_HOST=0.0.0.0
EPP_PORT=700
EPP_CERT=/path/to/server.crt
EPP_KEY=/path/to/server.key
EPP_CA=/path/to/ca.crt

# Logging
LOG_LEVEL=INFO
EOF

# Set proper permissions
chmod 600 /path/to/epp-server/.env
```

### Step 2: Verify Database Connection

```bash
cd /path/to/epp-server

# Activate virtual environment
source venv/bin/activate

# Test database connection
python3 -c "
from src.database.connection import get_db_pool
import asyncio

async def test():
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute('SELECT 1 FROM DUAL')
            result = await cur.fetchone()
            print(f'Database connection OK: {result}')

asyncio.run(test())
"
```

### Step 3: Initialize Database Schema

If starting fresh, run the schema creation scripts:

```bash
# Connect to Oracle and run schema scripts
sqlplus epp_user/password@//host:1521/EPPDB @schema/create_tables.sql
sqlplus epp_user/password@//host:1521/EPPDB @schema/create_indexes.sql
sqlplus epp_user/password@//host:1521/EPPDB @schema/seed_data.sql
```

### Step 4: Generate Server Certificates

```bash
mkdir -p /path/to/epp-certs
cd /path/to/epp-certs

# Generate CA (if self-signing)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/C=AE/ST=Abu Dhabi/O=AEDA/CN=EPP CA"

# Generate server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/C=AE/ST=Abu Dhabi/O=AEDA/CN=epp.aeda.ae"

# Sign server certificate with CA
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt

# Set permissions
chmod 600 server.key ca.key
chmod 644 server.crt ca.crt
```

### Step 5: Create Registrar Account

```sql
-- Connect to database and create registrar account
INSERT INTO ACCOUNTS (
    ACC_ID, ACC_NAME, ACC_CLID, ACC_PASSWORD_HASH,
    ACC_STATUS, ACC_BALANCE, ACC_CREDIT_LIMIT
) VALUES (
    ACCOUNTS_SEQ.NEXTVAL,
    'Test Registrar',
    'testregistrar',
    -- Use bcrypt or similar for password hashing
    '$2b$12$hash_of_password_here',
    'ACTIVE',
    10000.00,
    5000.00
);
COMMIT;
```

### Step 6: Sign Registrar Certificate

When a registrar submits a CSR:

```bash
# Sign registrar CSR with CA
openssl x509 -req -days 365 \
    -in registrar.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out registrar.crt

# Send registrar.crt back to registrar
```

### Step 7: Start EPP Server

```bash
cd /path/to/epp-server
source venv/bin/activate

# Start server
python3 -m src.main

# Or with systemd service
sudo systemctl start epp-server
```

### Step 8: Verify Server is Running

```bash
# Check port is listening
netstat -tlnp | grep 700

# Check logs
tail -f /var/log/epp-server/epp.log

# Test with openssl
openssl s_client -connect localhost:700 \
    -cert /path/to/test-client.crt \
    -key /path/to/test-client.key \
    -CAfile /path/to/ca.crt
```

---

## Security Notes

1. **Never commit certificates or passwords** to version control
2. **Use environment variables** for passwords: `export EPP_PASSWORD='...'`
3. **Restrict key file permissions**: `chmod 600 registrar.key`
4. **Use OT&E first** - never test directly in production
5. **Keep certificates secure** - they grant full registrar access
6. **Monitor certificate expiry** - renew before expiration
7. **Database credentials** - store in `.env` file with restricted permissions
