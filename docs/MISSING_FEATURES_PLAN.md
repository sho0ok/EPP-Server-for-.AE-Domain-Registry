# Missing Features Implementation Plan

## Overview

This document outlines the implementation plan for achieving 100% feature parity with the ARI C++ EPP Toolkit. Currently at ~89% parity, the following extensions need to be implemented.

## Missing Extensions Summary

| Phase | Extension | Complexity | Priority | Estimated Effort |
|-------|-----------|------------|----------|------------------|
| 7 | secDNS (DNSSEC) | High | High | Large |
| 8 | IDN Extension | Medium | Medium | Medium |
| 9 | Variant Extension | Medium | Medium | Medium |
| 10 | Sync Extension | Low | Low | Small |
| 11 | KV Extension | Low | Low | Small |
| 12 | Client Session Pool | Medium | Medium | Medium |

---

## Phase 7: secDNS Extension (DNSSEC)

**Namespace:** `urn:ietf:params:xml:ns:secDNS-1.1`

### Description
DNSSEC (Domain Name System Security Extensions) provides authentication and integrity to DNS responses. This extension allows registrars to manage DS (Delegation Signer) and DNSKEY records.

### Data Structures

#### DS Data (Delegation Signer)
```python
@dataclass
class DSData:
    """DNSSEC Delegation Signer record."""
    key_tag: int        # 0-65535 (unsigned short)
    alg: int            # Algorithm number (0-255)
    digest_type: int    # Digest type (0-255)
    digest: str         # Hex-encoded digest
    key_data: Optional['KeyData'] = None  # Optional associated key
```

#### Key Data (DNSKEY)
```python
@dataclass
class KeyData:
    """DNSSEC Key record."""
    flags: int          # 0-65535 (256=ZSK, 257=KSK)
    protocol: int       # Always 3 for DNSSEC
    alg: int            # Algorithm number
    pub_key: str        # Base64-encoded public key
```

### Commands to Implement

#### 1. secDNS:create (Command Extension)
Attach DNSSEC data to domain:create command.

```xml
<extension>
  <secDNS:create xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">
    <secDNS:maxSigLife>604800</secDNS:maxSigLife>
    <secDNS:dsData>
      <secDNS:keyTag>12345</secDNS:keyTag>
      <secDNS:alg>8</secDNS:alg>
      <secDNS:digestType>2</secDNS:digestType>
      <secDNS:digest>49FD46E6C4B45C55D4AC</secDNS:digest>
    </secDNS:dsData>
  </secDNS:create>
</extension>
```

#### 2. secDNS:update (Command Extension)
Add, remove, or change DNSSEC data.

- **add**: Add new DS/Key records
- **rem**: Remove DS/Key records (or `<all>true</all>` to remove all)
- **chg**: Change maxSigLife
- **urgent** attribute: Request immediate processing

#### 3. secDNS:infData (Response Extension)
Return DNSSEC data in domain:info response.

### Server Implementation Tasks

1. **Database Schema**
   - Create `DNSSEC_DS` table for DS records
   - Create `DNSSEC_KEY` table for Key records
   - Link to domains via ROID

2. **XML Processing**
   - Add `SECDNS_NS` to xml_processor.py
   - Parse secDNS:create extension
   - Parse secDNS:update extension
   - Parse secDNS:infData response

3. **Command Handlers**
   - Modify domain:create to handle secDNS extension
   - Modify domain:update to handle secDNS extension
   - Modify domain:info to return secDNS data

4. **Response Builder**
   - Add `build_secdns_info_data()` method

5. **Validation**
   - Validate algorithm numbers (common: 5, 7, 8, 10, 13, 14, 15, 16)
   - Validate digest types (1=SHA-1, 2=SHA-256, 4=SHA-384)
   - Validate key flags
   - Validate base64/hex encoding

### Client Implementation Tasks

1. **Models**
   - Add DSData, KeyData dataclasses
   - Add SecDNSInfo dataclass

2. **XML Builder**
   - `build_domain_create_with_secdns()`
   - `build_domain_update_with_secdns()`

3. **XML Parser**
   - `parse_secdns_info_extension()`

4. **Client Methods**
   - `domain_create()` - add secdns parameter
   - `domain_update_secdns()` - add/rem/chg DNSSEC
   - `domain_info()` - return SecDNSInfo

5. **CLI Commands**
   - `domain create --ds-data "12345,8,2,ABCD..."`
   - `domain update-dnssec --add-ds "..." --rem-ds "..."`
   - `domain info` - show DNSSEC data

---

## Phase 8: IDN Extension (Internationalized Domain Names)

**Namespace:** `urn:X-ar:params:xml:ns:idnadomain-1.0`

### Description
Supports internationalized domain names by maintaining both user-form (Unicode) and DNS-form (Punycode/ACE) representations.

### Data Structures

```python
@dataclass
class IDNData:
    """IDN domain name representation."""
    user_form: str      # Unicode form (e.g., "münchen.de")
    dns_form: str       # ACE/Punycode form (e.g., "xn--mnchen-3ya.de")
    language: str       # BCP 47 language tag (e.g., "de")
    canonical_form: Optional[str] = None  # Server canonical form
```

### Commands to Implement

#### 1. idnadomain:create (Command Extension)
```xml
<extension>
  <idnadomain:create xmlns:idnadomain="urn:X-ar:params:xml:ns:idnadomain-1.0">
    <idnadomain:userForm language="ar">مثال.ae</idnadomain:userForm>
  </idnadomain:create>
</extension>
```

#### 2. idnadomain:infData / idnadomain:creData (Response Extension)
```xml
<extension>
  <idnadomain:infData>
    <idnadomain:userForm language="ar">مثال.ae</idnadomain:userForm>
    <idnadomain:canonicalForm>xn--mgbh0fb.ae</idnadomain:canonicalForm>
  </idnadomain:infData>
</extension>
```

### Implementation Tasks

1. **Server**
   - Add IDN_NS to xml_processor.py
   - Store user_form and language in database
   - Parse idnadomain:create extension
   - Build idnadomain:infData/creData response

2. **Client**
   - Add IDNData model
   - Add build_domain_create_with_idn()
   - Add parse_idn_info_extension()
   - CLI: `domain create --idn-user-form "مثال" --idn-language "ar"`

3. **Validation**
   - Validate BCP 47 language tags
   - Validate Punycode conversion
   - Ensure user_form and dns_form consistency

---

## Phase 9: Variant Extension

**Namespace:** `urn:X-ar:params:xml:ns:variant-1.0`

### Description
Manages domain name variants (e.g., simplified/traditional Chinese characters, different scripts for the same word).

### Data Structures

```python
@dataclass
class DomainVariant:
    """Domain variant representation."""
    name: str           # DNS form of variant
    user_form: str      # User-readable form
```

### Commands to Implement

#### 1. variant:info (Command Extension)
Query variant information with attribute `variants="all"` or `variants="none"`.

#### 2. variant:update (Command Extension)
Add or remove variants.

```xml
<extension>
  <variant:update xmlns:variant="urn:X-ar:params:xml:ns:variant-1.0">
    <variant:add>
      <variant:variant userForm="例子">xn--fsqu00a</variant:variant>
    </variant:add>
  </variant:update>
</extension>
```

#### 3. variant:infData / variant:creData (Response Extension)
Return variant list in responses.

#### 4. variant:variantInfo (Protocol Extension Command)
Query specific variant information.

### Implementation Tasks

1. **Server**
   - Add VARIANT_NS to xml_processor.py
   - Create DOMAIN_VARIANTS table
   - Parse variant:info, variant:update, variant:variantInfo
   - Build variant:infData/creData response

2. **Client**
   - Add DomainVariant model
   - Add variant command builders
   - Add variant response parsers
   - CLI: `domain info --variants all`

---

## Phase 10: Sync Extension (Expiry Date Synchronization)

**Namespace:** `urn:X-ar:params:xml:ns:sync-1.0`

### Description
Allows synchronization of domain expiry dates to a specific date.

### Commands to Implement

#### sync:update (Command Extension)
```xml
<extension>
  <sync:update xmlns:sync="urn:X-ar:params:xml:ns:sync-1.0">
    <sync:exDate>2025-12-31T23:59:59.0Z</sync:exDate>
  </sync:update>
</extension>
```

### Implementation Tasks

1. **Server**
   - Add SYNC_NS to xml_processor.py
   - Parse sync:update in domain:update
   - Update domain expiry date with billing adjustment

2. **Client**
   - Add build_domain_update_with_sync()
   - CLI: `domain sync example.ae --exp-date 2025-12-31`

---

## Phase 11: KV Extension (Key-Value Store)

**Namespace:** `urn:X-ar:params:xml:ns:kv-1.0`

### Description
Stores arbitrary key-value pairs associated with domains. Used for registry-specific metadata.

### Data Structures

```python
@dataclass
class KVItem:
    """Key-value item."""
    key: str
    value: str

@dataclass
class KVList:
    """Named list of key-value items."""
    name: str
    items: List[KVItem]
```

### Commands to Implement

#### 1. kv:create (Command Extension)
```xml
<extension>
  <kv:create xmlns:kv="urn:X-ar:params:xml:ns:kv-1.0">
    <kv:kvlist name="metadata">
      <kv:item key="category">premium</kv:item>
      <kv:item key="source">auction</kv:item>
    </kv:kvlist>
  </kv:create>
</extension>
```

#### 2. kv:update (Command Extension)
Replace key-value lists.

#### 3. kv:infData (Response Extension)
Return stored key-value data.

### Implementation Tasks

1. **Server**
   - Add KV_NS to xml_processor.py
   - Create DOMAIN_KV table (domain_roid, list_name, key, value)
   - Parse kv:create, kv:update
   - Build kv:infData response

2. **Client**
   - Add KVList, KVItem models
   - Add KV command builders/parsers
   - CLI: `domain create --kv "metadata:category=premium,source=auction"`

---

## Phase 12: Client Session Pool

### Description
Connection pooling for the EPP client to improve performance and resource utilization.

### Features to Implement

1. **SessionPool Class**
   ```python
   class SessionPool:
       def __init__(self, config: SessionPoolConfig):
           self.min_connections: int
           self.max_connections: int
           self.idle_timeout: int
           self.connection_timeout: int

       async def acquire(self) -> EPPClient
       async def release(self, client: EPPClient)
       async def close_all()
   ```

2. **Configuration**
   - Minimum pool size
   - Maximum pool size
   - Idle connection timeout
   - Connection acquisition timeout
   - Health check interval

3. **Features**
   - Automatic connection health checks
   - Connection recycling
   - Graceful shutdown
   - Connection reuse tracking

---

## Implementation Priority Order

### High Priority (Production Critical)
1. **Phase 7: secDNS** - Required for DNSSEC-enabled zones

### Medium Priority (Expanded Functionality)
2. **Phase 8: IDN Extension** - Required for Arabic/Unicode domains
3. **Phase 9: Variant Extension** - Required for IDN variant management
4. **Phase 12: Client Session Pool** - Performance improvement

### Low Priority (Nice to Have)
5. **Phase 10: Sync Extension** - Utility feature
6. **Phase 11: KV Extension** - Metadata storage

---

## Estimated Timeline

| Phase | Extension | Est. Time |
|-------|-----------|-----------|
| 7 | secDNS | 2-3 days |
| 8 | IDN | 1-2 days |
| 9 | Variant | 1-2 days |
| 10 | Sync | 0.5 days |
| 11 | KV | 0.5 days |
| 12 | Session Pool | 1-2 days |
| **Total** | | **7-11 days** |

---

## File Changes Summary

### Server Files to Modify/Create

| File | Changes |
|------|---------|
| `src/core/xml_processor.py` | Add 5 new namespace constants, parsing methods |
| `src/utils/response_builder.py` | Add 5 new response builder methods |
| `src/commands/domain.py` | Handle new extensions in create/update/info |
| `src/database/repositories/extension_repo.py` | Add DNSSEC, IDN, Variant, KV repositories |
| `src/database/models.py` | Add new table models |

### Client Files to Modify/Create

| File | Changes |
|------|---------|
| `src/epp_client/models.py` | Add DSData, KeyData, IDNData, DomainVariant, KVList |
| `src/epp_client/xml_builder.py` | Add 5 new extension builders |
| `src/epp_client/xml_parser.py` | Add 5 new extension parsers |
| `src/epp_client/client.py` | Add new methods for extensions |
| `src/epp_cli/main.py` | Add CLI commands for new extensions |
| `src/epp_client/session_pool.py` | New file for connection pooling |

---

## Testing Plan

For each phase:
1. Unit tests for XML parsing
2. Unit tests for response building
3. Integration tests with test server
4. CLI command tests
5. Update test suite with new extension tests

---

## Success Criteria

- [x] All 6 missing extensions implemented
- [x] 100% feature parity with C++ toolkit
- [ ] All new features have test coverage
- [x] CLI commands for all new features
- [x] Documentation updated

---

## Implementation Status (Completed)

All phases have been implemented:

### Server Implementation
- **xml_processor.py**: Added namespace constants and parsing methods for all 5 extensions
- **response_builder.py**: Added response builder methods for secDNS, IDN, Variant, KV
- **extension_repo.py**: Added CRUD methods for DNSSEC, IDN, Variant, KV data
- **domain.py**: Updated handlers to process and return extension data
- **phase7_11_schema.sql**: Database schema for new extension tables

### Client Implementation
- **models.py**: Added DSData, KeyData, SecDNSInfo, IDNData, DomainVariant, VariantInfo, KVItem, KVList, KVInfo
- **xml_builder.py**: Added XML builders for all extensions
- **xml_parser.py**: Added XML parsers for all extensions
- **client.py**: Added client methods for all extension operations
- **main.py (CLI)**: Added commands for dnssec, idn, variant, sync, kv

### Session Pool
- Already existed in pool.py with full functionality
