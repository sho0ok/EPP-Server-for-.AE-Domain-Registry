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
