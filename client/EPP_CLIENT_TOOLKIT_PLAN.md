# EPP Client Toolkit - Build Plan

## Overview

A production-ready Python EPP client toolkit for registrars to connect to the .AE EPP server.

**Location:** `/home/alhammadi/Downloads/ARI/epp-client/`

---

## Goals

1. Full EPP protocol support (RFC 5730-5734)
2. TLS 1.2+ with client certificate authentication
3. Support all .AE registry operations
4. Easy integration for registrars
5. CLI tool for operations and testing
6. Production-ready with logging and error handling

---

## Tech Stack

| Component | Technology | Notes |
|-----------|------------|-------|
| Language | Python 3.9+ | Match server |
| TLS | `ssl` (stdlib) | TLS 1.2/1.3 |
| XML | `lxml` | Already in server |
| Async | `asyncio` | High performance |
| CLI | `click` | User-friendly CLI |
| Config | `pyyaml` | Already in server |
| Logging | `logging` | Stdlib |

**New dependency:** `click` (for CLI)

---

## Directory Structure

```
/home/alhammadi/Downloads/ARI/epp-client/
├── src/
│   └── epp_client/
│       ├── __init__.py           # Package exports
│       ├── client.py             # Main EPPClient class
│       ├── connection.py         # TLS connection handling
│       ├── framing.py            # EPP 4-byte frame encode/decode
│       ├── xml_builder.py        # Build EPP XML commands
│       ├── xml_parser.py         # Parse EPP XML responses
│       ├── commands/
│       │   ├── __init__.py
│       │   ├── session.py        # login, logout, hello, poll
│       │   ├── domain.py         # domain:* commands
│       │   ├── contact.py        # contact:* commands
│       │   └── host.py           # host:* commands
│       ├── models.py             # Data classes for requests/responses
│       └── exceptions.py         # Custom exceptions
│
├── src/epp_cli/
│   ├── __init__.py
│   ├── main.py                   # CLI entry point
│   ├── commands/                 # CLI command handlers
│   │   ├── domain.py
│   │   ├── contact.py
│   │   └── host.py
│   └── formatters.py             # Output formatting (text/json/xml)
│
├── tests/
│   ├── test_connection.py
│   ├── test_framing.py
│   ├── test_xml_builder.py
│   ├── test_xml_parser.py
│   └── test_commands.py
│
├── examples/
│   ├── basic_usage.py
│   ├── domain_lifecycle.py
│   ├── bulk_check.py
│   ├── transfer_workflow.py
│   └── async_operations.py
│
├── config/
│   └── sample_config.yaml
│
├── requirements.txt
├── setup.py
├── README.md
└── EPP_CLIENT_TOOLKIT_PLAN.md
```

---

## Phase 1: Core Library

### 1.1 Connection Layer (`connection.py`)

```python
class EPPConnection:
    """
    Handles TLS connection to EPP server.

    Features:
    - TLS 1.2+ with client certificate
    - Connection timeout handling
    - Auto-reconnect capability
    - Keep-alive support
    """

    def __init__(self, host, port, cert_file, key_file, ca_file, timeout)
    def connect()
    def disconnect()
    def is_connected()
    def send(data: bytes)
    def receive() -> bytes
```

### 1.2 Framing Layer (`framing.py`)

```python
def encode_frame(data: bytes) -> bytes:
    """Add 4-byte length prefix."""

def decode_frame(data: bytes) -> bytes:
    """Remove 4-byte length prefix."""

def read_frame(connection) -> bytes:
    """Read complete EPP frame from connection."""

def write_frame(connection, data: bytes):
    """Write EPP frame to connection."""
```

### 1.3 XML Builder (`xml_builder.py`)

```python
class XMLBuilder:
    """
    Builds EPP XML commands.

    Methods for each command type:
    - build_hello()
    - build_login(client_id, password, ...)
    - build_logout()
    - build_domain_check(names)
    - build_domain_info(name, auth_info)
    - build_domain_create(name, period, registrant, contacts, ns, ...)
    - build_domain_update(name, add, rem, chg)
    - build_domain_delete(name)
    - build_domain_renew(name, cur_exp_date, period)
    - build_domain_transfer(name, auth_info, op)
    - build_contact_check(ids)
    - build_contact_info(id, auth_info)
    - build_contact_create(id, postal_info, email, ...)
    - build_contact_update(id, add, rem, chg)
    - build_contact_delete(id)
    - build_host_check(names)
    - build_host_info(name)
    - build_host_create(name, addrs)
    - build_host_update(name, add, rem, chg)
    - build_host_delete(name)
    - build_poll(op, msg_id)
    """
```

### 1.4 XML Parser (`xml_parser.py`)

```python
class XMLParser:
    """
    Parses EPP XML responses.

    Returns structured response objects with:
    - result_code
    - message
    - data (command-specific)
    - client_transaction_id
    - server_transaction_id
    """

    def parse(xml_bytes) -> EPPResponse
    def parse_greeting(xml) -> Greeting
    def parse_domain_check(xml) -> DomainCheckResult
    def parse_domain_info(xml) -> DomainInfo
    # ... etc for all response types
```

### 1.5 Models (`models.py`)

```python
@dataclass
class Greeting:
    server_id: str
    server_date: datetime
    version: str
    lang: List[str]
    obj_uris: List[str]
    ext_uris: List[str]

@dataclass
class EPPResponse:
    code: int
    message: str
    cl_trid: str
    sv_trid: str
    data: Any
    success: bool

@dataclass
class DomainCheckResult:
    results: List[dict]  # [{name, available, reason}]

@dataclass
class DomainInfo:
    name: str
    roid: str
    status: List[str]
    registrant: str
    contacts: List[dict]
    nameservers: List[str]
    clID: str
    crDate: datetime
    exDate: datetime
    # ... etc

@dataclass
class ContactInfo:
    id: str
    roid: str
    status: List[str]
    postal_info: dict
    voice: str
    email: str
    # ... etc

@dataclass
class HostInfo:
    name: str
    roid: str
    status: List[str]
    addresses: List[dict]
    # ... etc

# Request models
@dataclass
class DomainCreate:
    name: str
    period: int = 1
    period_unit: str = "y"
    registrant: str
    admin: str = None
    tech: str = None
    billing: str = None
    nameservers: List[str] = None
    auth_info: str = None

# ... etc for other create/update requests
```

### 1.6 Exceptions (`exceptions.py`)

```python
class EPPError(Exception):
    """Base EPP exception."""
    code: int
    message: str

class EPPConnectionError(EPPError):
    """Connection failed."""

class EPPAuthenticationError(EPPError):
    """Login failed."""

class EPPCommandError(EPPError):
    """Command execution failed."""

class EPPObjectNotFound(EPPCommandError):
    """Object does not exist (2303)."""

class EPPObjectExists(EPPCommandError):
    """Object already exists (2302)."""

class EPPAuthorizationError(EPPCommandError):
    """Not authorized (2201)."""

class EPPParameterError(EPPCommandError):
    """Invalid parameter (2005)."""
```

### 1.7 Main Client (`client.py`)

```python
class EPPClient:
    """
    Main EPP client interface.

    Usage:
        client = EPPClient("epp.aeda.ae", cert="client.crt", key="client.key")
        client.connect()
        client.login("user", "password")

        # Domain operations
        result = client.domain_check(["example.ae"])
        info = client.domain_info("example.ae")
        client.domain_create(DomainCreate(name="new.ae", ...))

        client.logout()
        client.disconnect()

    Context manager support:
        with EPPClient(...) as client:
            client.login(...)
            # operations
            client.logout()

    Async support:
        async with AsyncEPPClient(...) as client:
            await client.login(...)
            result = await client.domain_check(...)
    """

    # Connection
    def __init__(self, host, port=700, cert_file, key_file, ca_file=None,
                 timeout=30, auto_reconnect=True)
    def connect() -> Greeting
    def disconnect()
    def is_connected() -> bool

    # Session
    def login(client_id, password, new_password=None) -> EPPResponse
    def logout() -> EPPResponse
    def hello() -> Greeting
    def poll(op="req", msg_id=None) -> EPPResponse

    # Domain
    def domain_check(names: List[str]) -> DomainCheckResult
    def domain_info(name, auth_info=None) -> DomainInfo
    def domain_create(domain: DomainCreate) -> EPPResponse
    def domain_update(name, add=None, rem=None, chg=None) -> EPPResponse
    def domain_delete(name) -> EPPResponse
    def domain_renew(name, cur_exp_date, period=1) -> EPPResponse
    def domain_transfer(name, auth_info, op="request") -> EPPResponse

    # Contact
    def contact_check(ids: List[str]) -> ContactCheckResult
    def contact_info(id, auth_info=None) -> ContactInfo
    def contact_create(contact: ContactCreate) -> EPPResponse
    def contact_update(id, add=None, rem=None, chg=None) -> EPPResponse
    def contact_delete(id) -> EPPResponse

    # Host
    def host_check(names: List[str]) -> HostCheckResult
    def host_info(name) -> HostInfo
    def host_create(name, addresses=None) -> EPPResponse
    def host_update(name, add=None, rem=None, chg=None) -> EPPResponse
    def host_delete(name) -> EPPResponse

    # Raw
    def send_raw(xml: str) -> str
```

---

## Phase 2: CLI Tool

### 2.1 CLI Structure

```
epp-cli [OPTIONS] COMMAND [ARGS]

Options:
  -h, --host TEXT       EPP server hostname
  -p, --port INTEGER    EPP port (default: 700)
  -c, --cert FILE       Client certificate
  -k, --key FILE        Client key
  --ca FILE             CA certificate
  --config FILE         Config file
  -f, --format TEXT     Output format: text|json|xml
  -v, --verbose         Verbose output
  --help                Show help

Commands:
  connect     Connect and show greeting
  login       Login to server
  logout      Logout from server

  domain      Domain commands
    check     Check availability
    info      Get domain info
    create    Create domain
    update    Update domain
    delete    Delete domain
    renew     Renew domain
    transfer  Transfer domain

  contact     Contact commands
    check     Check availability
    info      Get contact info
    create    Create contact
    update    Update contact
    delete    Delete contact

  host        Host commands
    check     Check availability
    info      Get host info
    create    Create host
    update    Update host
    delete    Delete host

  poll        Poll for messages

  shell       Interactive mode
  batch       Run commands from file
```

### 2.2 CLI Examples

```bash
# Quick domain check
epp-cli -c client.crt -k client.key domain check example.ae test.ae

# With config file
epp-cli --config ~/.epp.yaml domain check example.ae

# Interactive shell
epp-cli --config ~/.epp.yaml shell
EPP> login
EPP> domain check example.ae
EPP> domain info example.ae
EPP> logout
EPP> exit

# Batch mode
epp-cli --config ~/.epp.yaml batch commands.txt

# JSON output
epp-cli --config ~/.epp.yaml -f json domain info example.ae
```

### 2.3 Config File Format

```yaml
# ~/.epp.yaml
host: epp.aeda.ae
port: 700
cert: /path/to/client.crt
key: /path/to/client.key
ca: /path/to/ca.crt
username: registrar1
# password from env: EPP_PASSWORD
timeout: 30
format: text
```

---

## Phase 3: Advanced Features

### 3.1 Async Client

```python
class AsyncEPPClient:
    """Async version for high-volume operations."""

    async def connect()
    async def login(...)
    async def domain_check(...)
    # ... all methods async
```

### 3.2 Connection Pool

```python
class EPPConnectionPool:
    """
    Pool of EPP connections for concurrent operations.

    Usage:
        pool = EPPConnectionPool(host, cert, key, size=5)
        pool.start()

        # Automatic connection management
        result = await pool.domain_check(["example.ae"])

        pool.stop()
    """

    def __init__(self, host, ..., pool_size=5, max_size=20)
    async def start()
    async def stop()
    async def execute(command) -> EPPResponse
```

### 3.3 Auto-reconnect

```python
# Built into EPPClient
client = EPPClient(..., auto_reconnect=True, max_retries=3)

# Automatically reconnects on:
# - Connection drop
# - Session timeout
# - Server disconnect
```

### 3.4 Transaction Logging

```python
# Enable logging
client = EPPClient(..., log_transactions=True, log_file="epp.log")

# Log format:
# 2024-01-17 10:30:00 | REQUEST  | domain:check | example.ae
# 2024-01-17 10:30:01 | RESPONSE | 1000 | Command completed successfully
```

---

## Phase 4: Testing & Examples

### 4.1 Test Suite

```
tests/
├── test_connection.py      # TLS connection tests
├── test_framing.py         # Frame encode/decode tests
├── test_xml_builder.py     # XML generation tests
├── test_xml_parser.py      # XML parsing tests
├── test_client.py          # Integration tests
└── test_cli.py             # CLI tests
```

### 4.2 Examples

```
examples/
├── basic_usage.py          # Simple connect/login/check/logout
├── domain_lifecycle.py     # Create -> update -> renew -> delete
├── bulk_check.py           # Check 1000 domains efficiently
├── transfer_workflow.py    # Full transfer flow
├── async_operations.py     # Async batch processing
└── error_handling.py       # Proper error handling patterns
```

---

## Build Phases

| Phase | Description | Deliverables | Est. Files |
|-------|-------------|--------------|------------|
| **Phase 1** | Core Library | connection, framing, xml, client | 10 files |
| **Phase 2** | CLI Tool | CLI commands, formatters | 8 files |
| **Phase 3** | Advanced | async, pool, auto-reconnect | 3 files |
| **Phase 4** | Testing | tests, examples, docs | 12 files |

---

## Dependencies

```
# requirements.txt
lxml>=4.9.0
pyyaml>=6.0
click>=8.0.0
```

---

## Deliverables

1. **Python Package** (`epp-client`) - installable via pip
2. **CLI Tool** (`epp-cli`) - standalone command
3. **Documentation** - README, API docs, examples
4. **Test Suite** - unit and integration tests
5. **Sample Config** - ready-to-use configuration

---

## Usage After Build

**Install:**
```bash
pip install ./epp-client
# or
pip install epp-client  # if published to PyPI
```

**Library:**
```python
from epp_client import EPPClient

client = EPPClient("epp.aeda.ae", cert="client.crt", key="client.key")
client.login("user", "pass")
print(client.domain_check(["example.ae"]))
client.logout()
```

**CLI:**
```bash
epp-cli --config config.yaml domain check example.ae
```

---

## Timeline

| Phase | Components |
|-------|------------|
| Phase 1 | Core Library (connection, framing, XML, client) |
| Phase 2 | CLI Tool |
| Phase 3 | Advanced Features (async, pool) |
| Phase 4 | Tests, Examples, Documentation |

---

## Notes

- Reuse patterns from epp-server where applicable
- All XML follows RFC 5730-5734
- Support .AE extensions (aeext-1.0)
- TLS 1.2 minimum (match server requirement)
- Full error handling with meaningful messages
- Production-ready logging
