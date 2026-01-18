# EPP Client Toolkit

A production-ready Python EPP (Extensible Provisioning Protocol) client toolkit for domain registrars. Supports RFC 5730-5734 with TLS 1.2+ security.

## Quick Start

### 1. Clone & Install
```bash
git clone https://github.com/sho0ok/EPP-Server-for-.AE-Domain-Registry.git
cd EPP-Server-for-.AE-Domain-Registry/client
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### 2. Generate Certificate
```bash
mkdir -p ~/epp-certs && cd ~/epp-certs
openssl genrsa -out registrar.key 2048
openssl req -new -key registrar.key -out registrar.csr \
    -subj "/C=AE/O=Your Company/CN=your-registrar-id"
```

### 3. Submit CSR to Registry
- Upload `registrar.csr` to registry portal
- Download signed `registrar.crt` and `ca.crt`

### 4. Connect
```bash
export EPP_PASSWORD='your-password'

epp --host epp.registry.ae --port 700 \
    --cert ~/epp-certs/registrar.crt \
    --key ~/epp-certs/registrar.key \
    --ca ~/epp-certs/ca.crt \
    -u your-registrar-id \
    domain check example.ae
```

---

## Features

- **Full EPP Support**: Domain, Contact, and Host object management
- **TLS 1.2+ Security**: Modern TLS with client certificate authentication
- **Multiple APIs**:
  - Synchronous client for simple operations
  - Async client for high-performance applications
  - Connection pool for concurrent operations
- **CLI Tool**: Command-line interface for quick operations
- **RFC Compliant**: Implements RFC 5730-5734 (EPP core specifications)

## Installation

### From Source

```bash
cd epp-client
pip install -e .
```

### Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- lxml >= 4.9.0
- pyyaml >= 6.0
- click >= 8.0.0
- python-dateutil >= 2.8.0

## Quick Start

### Python API

```python
from epp_client import EPPClient

# Create client
client = EPPClient(
    host="epp.registry.ae",
    port=700,
    cert_file="client.crt",
    key_file="client.key",
    ca_file="ca.crt",
)

# Connect and login
with client:
    client.login("registrar_id", "password")

    # Check domain availability
    result = client.domain_check(["example.ae", "test.ae"])
    for item in result.results:
        print(f"{item.name}: {'available' if item.available else 'taken'}")

    # Create a domain
    result = client.domain_create(
        name="newdomain.ae",
        registrant="contact123",
        admin="admin123",
        tech="tech123",
        nameservers=["ns1.example.ae", "ns2.example.ae"],
    )
    print(f"Created: {result.name}, expires: {result.ex_date}")

    client.logout()
```

### CLI Tool

```bash
# Initialize configuration
epp config init

# Check domain availability
epp --host epp.registry.ae --cert client.crt --key client.key \
    --client-id registrar1 domain check example.ae test.ae

# Get domain info
epp domain info example.ae

# Create a domain
epp domain create newdomain.ae --registrant contact123 --admin admin123

# Using config file
epp -c config.yaml domain check example.ae
```

## Configuration

Create a configuration file at `~/.epp/config.yaml`:

```yaml
server:
  host: epp.registry.ae
  port: 700
  timeout: 30
  verify_server: true

certs:
  cert_file: ~/.epp/client.crt
  key_file: ~/.epp/client.key
  ca_file: ~/.epp/ca.crt

credentials:
  client_id: your_registrar_id
  # password: your_password  # Optional, will prompt if not set

# Multiple profiles
profiles:
  production:
    server:
      host: epp.registry.ae
    credentials:
      client_id: prod_registrar

  ote:
    server:
      host: epp-ote.registry.ae
    credentials:
      client_id: ote_registrar
```

## API Reference

### EPPClient (Synchronous)

```python
from epp_client import EPPClient

client = EPPClient(
    host="epp.registry.ae",
    port=700,
    cert_file="client.crt",
    key_file="client.key",
    ca_file="ca.crt",
    timeout=30,
    verify_server=True,
)

# Session Commands
client.connect()               # Connect and receive greeting
client.login(id, password)     # Login to server
client.logout()                # Logout from server
client.disconnect()            # Disconnect

# Domain Commands
client.domain_check(names)     # Check availability
client.domain_info(name)       # Get domain info
client.domain_create(...)      # Create domain
client.domain_delete(name)     # Delete domain
client.domain_renew(...)       # Renew domain
client.domain_update(...)      # Update domain
client.domain_transfer_request(name, auth_info)  # Request transfer
client.domain_transfer_query(name)               # Query transfer
client.domain_transfer_approve(name)             # Approve transfer
client.domain_transfer_reject(name)              # Reject transfer
client.domain_transfer_cancel(name)              # Cancel transfer

# Contact Commands
client.contact_check(ids)      # Check availability
client.contact_info(id)        # Get contact info
client.contact_create(...)     # Create contact
client.contact_delete(id)      # Delete contact
client.contact_update(...)     # Update contact

# Host Commands
client.host_check(names)       # Check availability
client.host_info(name)         # Get host info
client.host_create(...)        # Create host
client.host_delete(name)       # Delete host
client.host_update(...)        # Update host

# Poll Commands
client.poll_request()          # Get next message
client.poll_ack(msg_id)        # Acknowledge message
```

### AsyncEPPClient (Asynchronous)

```python
import asyncio
from epp_client import AsyncEPPClient

async def main():
    async with AsyncEPPClient(
        host="epp.registry.ae",
        cert_file="client.crt",
        key_file="client.key",
    ) as client:
        await client.login("registrar", "password")
        result = await client.domain_check(["example.ae"])
        await client.logout()

asyncio.run(main())
```

### Connection Pool

```python
from epp_client import create_pool

async def main():
    # Create connection pool
    pool = await create_pool(
        host="epp.registry.ae",
        client_id="registrar",
        password="password",
        cert_file="client.crt",
        key_file="client.key",
        min_connections=2,
        max_connections=10,
    )

    try:
        # Use pool
        async with pool.acquire() as client:
            result = await client.domain_check(["example.ae"])
    finally:
        await pool.stop()
```

## CLI Commands

```bash
# Configuration
epp config init              # Create sample config
epp config show              # Show current config

# Session
epp hello                    # Send hello, show greeting

# Domain operations
epp domain check NAME...     # Check availability
epp domain info NAME         # Get domain info
epp domain create NAME       # Create domain
epp domain delete NAME       # Delete domain
epp domain renew NAME        # Renew domain
epp domain transfer NAME OP  # Transfer operations
epp domain update NAME       # Update domain

# Contact operations
epp contact check ID...      # Check availability
epp contact info ID          # Get contact info
epp contact create ID        # Create contact
epp contact delete ID        # Delete contact
epp contact update ID        # Update contact

# Host operations
epp host check NAME...       # Check availability
epp host info NAME           # Get host info
epp host create NAME         # Create host
epp host delete NAME         # Delete host
epp host update NAME         # Update host

# Poll messages
epp poll request             # Get next message
epp poll ack MSG_ID          # Acknowledge message

# Options
--host, -h          Server hostname
--port              Server port (default: 700)
--cert              Client certificate file
--key               Client private key file
--ca                CA certificate file
--client-id, -u     Client/registrar ID
--password, -P      Password (or use EPP_PASSWORD env)
--config, -c        Config file path
--profile, -p       Config profile name
--format, -f        Output format (table, json, xml)
--quiet, -q         Suppress non-essential output
--debug             Enable debug logging
```

## Error Handling

```python
from epp_client import (
    EPPClient,
    EPPError,
    EPPConnectionError,
    EPPAuthenticationError,
    EPPCommandError,
    EPPObjectNotFound,
    EPPObjectExists,
)

try:
    with EPPClient(...) as client:
        client.login("id", "password")
        info = client.domain_info("example.ae")
except EPPConnectionError as e:
    print(f"Connection failed: {e}")
except EPPAuthenticationError as e:
    print(f"Login failed: {e}")
except EPPObjectNotFound as e:
    print(f"Domain not found: {e}")
except EPPObjectExists as e:
    print(f"Domain already exists: {e}")
except EPPCommandError as e:
    print(f"Command failed: {e} (code: {e.code})")
except EPPError as e:
    print(f"EPP error: {e}")
```

## Data Models

### Response Models

- `Greeting` - Server greeting
- `EPPResponse` - Generic response with code, message
- `DomainCheckResult` - Domain availability check results
- `DomainInfo` - Domain information
- `DomainCreateResult` - Domain creation result
- `DomainRenewResult` - Domain renewal result
- `DomainTransferResult` - Domain transfer result
- `ContactCheckResult` - Contact availability check results
- `ContactInfo` - Contact information
- `ContactCreateResult` - Contact creation result
- `HostCheckResult` - Host availability check results
- `HostInfo` - Host information
- `HostCreateResult` - Host creation result
- `PollMessage` - Poll queue message

### Request Models

- `DomainCreate` - Domain creation request
- `DomainUpdate` - Domain update request
- `ContactCreate` - Contact creation request
- `ContactUpdate` - Contact update request
- `HostCreate` - Host creation request
- `HostUpdate` - Host update request
- `PostalInfo` - Contact postal information

## Security

- TLS 1.2+ required (TLS 1.3 recommended)
- Client certificate authentication
- Server certificate verification
- Auth info passwords auto-generated with secure random

## Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=epp_client tests/
```

## Examples

See the `examples/` directory:

- `basic_usage.py` - Basic client usage
- `domain_operations.py` - Domain management examples
- `async_example.py` - Async client and pool examples

## License

MIT License

## Support

For issues and questions, please contact the AE Registry technical support.
