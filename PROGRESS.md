# EPP Server Build Progress

## Project Location
`/home/alhammadi/Downloads/ARI/epp-server/`

## Build Status Overview

| Phase | Description | Status | Completion |
|-------|-------------|--------|------------|
| Phase 1 | Foundation | COMPLETE | 100% |
| Phase 2 | Server Core | COMPLETE | 100% |
| Phase 3 | Session Management | COMPLETE | 100% |
| Phase 4 | Query Commands | COMPLETE | 100% |
| Phase 5 | Transform Commands | COMPLETE | 100% |
| Phase 6 | Deployment | COMPLETE | 100% |

---

## Phase 1 - Foundation (COMPLETE)

### Files Created:
- [x] `requirements.txt` - Dependencies (oracledb, lxml, pyyaml, cryptography)
- [x] `config/epp.yaml` - Server configuration
- [x] `config/logging.yaml` - Logging configuration
- [x] `src/__init__.py` - Package init with version
- [x] `src/core/__init__.py`
- [x] `src/commands/__init__.py`
- [x] `src/database/__init__.py`
- [x] `src/database/repositories/__init__.py`
- [x] `src/validators/__init__.py`
- [x] `src/utils/__init__.py`
- [x] `src/core/tls_handler.py` - TLS 1.2+ with client cert verification
- [x] `src/core/frame_handler.py` - EPP 4-byte length prefix framing
- [x] `src/database/connection.py` - Oracle async connection pool

### Key Features:
- TLS 1.2 minimum, TLS 1.3 supported
- Client certificate extraction (CN = registrar ID)
- Strong cipher suites
- EPP frame encoding/decoding (RFC 5734)
- Oracle connection pooling with oracledb
- Parameterized query support
- Sequence value retrieval

---

## Phase 2 - Server Core (COMPLETE)

### Files Created:
- [x] `src/core/xml_processor.py` - EPP XML parsing with lxml
- [x] `src/utils/response_builder.py` - EPP response XML templates
- [x] `src/server.py` - Main asyncio server

### Key Features:
- Secure XML parsing (no external entities)
- Full EPP namespace support
- All command parsers (login, logout, check, info, create, update, delete, renew, transfer)
- All RFC 5730 response codes
- Response builders for domain/contact/host
- Asyncio server with TLS
- Connection limit enforcement
- Graceful shutdown
- Signal handling (SIGTERM, SIGINT)

---

## Phase 3 - Session Management (COMPLETE)

### Files Created:
- [x] `src/database/models.py` - Dataclasses for all ARI tables
- [x] `src/database/repositories/transaction_repo.py` - CONNECTIONS, SESSIONS, TRANSACTIONS logging
- [x] `src/database/repositories/account_repo.py` - ACCOUNTS, USERS, ACCOUNT_EPP_ADDRESSES
- [x] `src/core/session_manager.py` - Session tracking
- [x] `src/commands/base.py` - Base command handler
- [x] `src/commands/session.py` - login, logout, hello, poll

### Key Features:
- Complete dataclasses for all ARI Oracle tables
- Connection logging to CONNECTIONS table
- Session logging to SESSIONS table
- Transaction logging to TRANSACTIONS table
- User authentication against USERS table
- IP whitelist verification (ACCOUNT_EPP_ADDRESSES)
- Account balance checking and debiting
- Connection limit enforcement per account
- Password hashing with timing-safe comparison
- Session state management
- Base command handler with error handling
- Login/logout/hello/poll command handlers

---

## Phase 4 - Query Commands (COMPLETE)

### Files Created:
- [x] `src/database/repositories/domain_repo.py` - Domain database operations
- [x] `src/database/repositories/contact_repo.py` - Contact database operations
- [x] `src/database/repositories/host_repo.py` - Host database operations
- [x] `src/commands/domain.py` - domain:check, domain:info
- [x] `src/commands/contact.py` - contact:check, contact:info
- [x] `src/commands/host.py` - host:check, host:info

### Key Features:
- Domain availability checking
- Domain info with contacts, nameservers, statuses
- Contact availability checking
- Contact info with postal info, phone, email
- Host availability checking
- Host info with IP addresses (v4/v6)
- Authorization checks for auth info disclosure
- Zone configuration retrieval
- Rate/pricing lookup
- Subordinate host detection
- Usage checks (is contact/host in use)
- ROID lookups for transaction logging

---

## Phase 5 - Transform Commands (COMPLETE)

### Files Created:
- [x] `src/utils/roid_generator.py` - Registry Object ID generation
- [x] `src/utils/password_utils.py` - Auth info handling
- [x] `src/validators/epp_validator.py` - Input validation
- [x] Updated `src/database/repositories/contact_repo.py` - create, update, delete operations
- [x] Updated `src/database/repositories/host_repo.py` - create, update, delete operations
- [x] Updated `src/database/repositories/domain_repo.py` - create, update, delete, renew, transfer operations
- [x] Completed `src/commands/contact.py` - create, update, delete handlers
- [x] Completed `src/commands/host.py` - create, update, delete handlers
- [x] Completed `src/commands/domain.py` - create, update, delete, renew, transfer handlers

### Key Features:
- ROID generation using OBJ_ROID_SEQ Oracle sequence
- Auth info generation with configurable policy
- Comprehensive input validation (domains, contacts, hosts, IPs, emails, phones)
- Contact CRUD operations with postal info and disclose flags
- Host CRUD operations with subordinate host detection
- Domain CRUD operations with zone configuration
- Domain renewal with expiry validation
- Domain transfer workflow (request, approve, reject, cancel, query)
- Billing integration (balance check and debit)
- Status management for all object types
- Transaction support for all write operations

---

## Phase 6 - Deployment (COMPLETE)

### Files Created:
- [x] `systemd/epp-server.service` - Systemd service unit file with security hardening
- [x] `scripts/generate_certs.sh` - TLS certificate generation script (CA, server, client)
- [x] `packaging/epp-server.spec` - RPM spec file (self-contained)
- [x] `packaging/build_rpm.sh` - RPM build script (downloads and bundles all deps)
- [x] `README.md` - Comprehensive installation and configuration guide

### Key Features:
- **Self-contained RPM** - All Python dependencies bundled in virtual environment
- **No internet required** - Works in air-gapped environments
- **Systemd integration** - Service management with security hardening
- **Certificate generator** - Creates CA, server, and client certificates
- **Automatic user creation** - Creates `epp` service account during install

### Deployment Approach: Self-Contained RPM

The RPM package is **fully self-contained** with all dependencies bundled:

```
/opt/epp-server/
├── venv/                    # Bundled Python virtual environment
│   └── lib/python3.x/site-packages/
│       ├── oracledb/        # Oracle database driver
│       ├── lxml/            # XML processing
│       ├── yaml/            # Configuration parsing
│       ├── cryptography/    # TLS and security
│       └── dateutil/        # Date calculations
├── src/                     # EPP server source code
├── config/
│   ├── epp.yaml            # Server configuration
│   ├── logging.yaml        # Logging configuration
│   └── tls/                # TLS certificates directory
├── logs/                    # Log files directory
├── run/                     # PID file directory
└── scripts/
    └── generate_certs.sh   # Certificate generator
```

### Build Instructions:
```bash
# Install build dependencies
dnf install python3 python3-pip python3-devel rpm-build \
    gcc libxml2-devel libxslt-devel openssl-devel

# Build the RPM (downloads and bundles all dependencies)
./packaging/build_rpm.sh

# RPM created at: packaging/epp-server-1.0.0-1.el9.x86_64.rpm
```

### Installation Steps:
```bash
# 1. Install Oracle Instant Client
dnf install oracle-instantclient-basic

# 2. Install EPP Server (no internet needed)
dnf install ./epp-server-1.0.0-1.el9.x86_64.rpm

# 3. Configure Oracle connection
vi /opt/epp-server/config/epp.yaml

# 4. Generate TLS certificates
/opt/epp-server/scripts/generate_certs.sh

# 5. Set Oracle password
export ORACLE_PASSWORD='your_password'

# 6. Enable and start service
systemctl enable epp-server
systemctl start epp-server
```

---

## ARI Oracle Schema Reference

### Key Tables:
- ACCOUNTS - Registrar accounts
- USERS - EPP users (login credentials)
- ACCOUNT_EPP_ADDRESSES - IP whitelist
- CONNECTIONS - Connection log
- SESSIONS - Session log
- TRANSACTIONS - Command log
- REGISTRY_OBJECTS - Base object table
- DOMAINS - Domain data
- DOMAIN_REGISTRATIONS - Registration periods
- DOMAIN_CONTACTS - Domain contact associations
- DOMAIN_NAMESERVERS - Domain nameserver associations
- CONTACTS - Contact data
- HOSTS - Host/nameserver data
- HOST_ADDRESSES - Host IP addresses
- EPP_DOMAIN_STATUSES - Domain EPP statuses
- EPP_CONTACT_STATUSES - Contact EPP statuses
- EPP_HOST_STATUSES - Host EPP statuses
- ZONES - TLD configuration
- TRANSFERS - Transfer records
- RATES - Pricing

### Key Sequences:
- CNN_ID_SEQ - CONNECTIONS.CNN_ID
- SES_ID_SEQ - SESSIONS.SES_ID
- TRN_ID_SEQ - TRANSACTIONS.TRN_ID
- DRE_ID_SEQ - DOMAIN_REGISTRATIONS.DRE_ID
- TRX_ID_SEQ - TRANSFERS.TRX_ID
- OBJ_ROID_SEQ - Registry Object IDs

### ROID Format:
```
<SEQUENCE>-AE
Example: 12345-AE
```

---

## Current Directory Structure

```
/home/alhammadi/Downloads/ARI/epp-server/
├── config/
│   ├── epp.yaml
│   └── logging.yaml
├── packaging/
├── schemas/
├── scripts/
├── src/
│   ├── __init__.py
│   ├── server.py
│   ├── commands/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── contact.py
│   │   ├── domain.py
│   │   ├── host.py
│   │   └── session.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── frame_handler.py
│   │   ├── session_manager.py
│   │   ├── tls_handler.py
│   │   └── xml_processor.py
│   ├── database/
│   │   ├── __init__.py
│   │   ├── connection.py
│   │   ├── models.py
│   │   └── repositories/
│   │       ├── __init__.py
│   │       ├── account_repo.py
│   │       ├── contact_repo.py
│   │       ├── domain_repo.py
│   │       ├── host_repo.py
│   │       └── transaction_repo.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── password_utils.py
│   │   ├── response_builder.py
│   │   └── roid_generator.py
│   └── validators/
│       ├── __init__.py
│       └── epp_validator.py
├── systemd/
│   └── epp-server.service
├── scripts/
│   └── generate_certs.sh
├── packaging/
│   ├── epp-server.spec
│   └── build_rpm.sh
├── requirements.txt
├── README.md
└── PROGRESS.md
```

---

## Notes

- All database operations use parameterized queries (SQL injection safe)
- EPP response codes follow RFC 5730
- Client IP captured from transport for CONNECTIONS.CNN_CLIENT_IP
- Server supports TLS 1.2 minimum per EPP requirements
- XML parser configured securely (no external entities, no network)
- Password verification uses timing-safe comparison to prevent timing attacks
- Session manager tracks all connection/session state
- Query commands support authorization checks for auth info disclosure

---

## Last Updated
Phase 6 completed - EPP Server build complete!

## Build Summary

All 6 phases completed successfully:
- **Phase 1**: Foundation (TLS, framing, Oracle connection pool)
- **Phase 2**: Server Core (XML processing, response builder, asyncio server)
- **Phase 3**: Session Management (authentication, logging, session tracking)
- **Phase 4**: Query Commands (check, info for domains/contacts/hosts)
- **Phase 5**: Transform Commands (create, update, delete, renew, transfer)
- **Phase 6**: Deployment (systemd, certificates, self-contained RPM)

The EPP server is ready for building and deployment.
