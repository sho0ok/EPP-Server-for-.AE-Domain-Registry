"""
Database Models for ARI Oracle Schema

Dataclasses representing all ARI database tables used by the EPP server.
These models match the exact column names and types in the ARI schema.
"""

from dataclasses import dataclass, field
from datetime import datetime, date
from typing import Optional, List
from decimal import Decimal


# ============================================================================
# Account & User Models
# ============================================================================

@dataclass
class Account:
    """ACCOUNTS table - Registrar accounts"""
    ACC_ID: int
    ACC_NAME: str
    ACC_STATUS: str  # Registry/Active/Suspended/Deleted
    ACC_BALANCE: Decimal
    ACC_CREDIT_LIMIT: Decimal
    ACC_CREDIT_LIMIT_ENABLED: str  # Y/N
    ACC_URL: str
    ACC_STREET1: str
    ACC_CITY: str
    ACC_STATE: str
    ACC_COUNTRY: str  # ISO 3166-1 alpha-2
    ACC_CREATE_DATE: date
    ACC_CLIENT_ID: Optional[str] = None  # EPP client ID (clID)
    ACC_EPP_MAX_CONNECTIONS: Optional[int] = None


@dataclass
class User:
    """USERS table - EPP users"""
    USR_ID: int
    USR_USERNAME: str
    USR_PASSWORD: str  # Password hash
    USR_TYPE: str  # WEB/EPP/SERVER
    USR_ACCOUNT_ID: int  # FK to ACCOUNTS
    USR_STATUS: str  # Active/Suspended/Deleted
    USR_FAILED_LOGIN_ATTEMPTS: int = 0
    USR_LAST_LOGON_DATE: Optional[date] = None


@dataclass
class AccountEPPAddress:
    """ACCOUNT_EPP_ADDRESSES table - IP whitelist"""
    AEA_ACC_ID: int  # FK to ACCOUNTS
    AEA_IP_ADDRESS: str  # Allowed IP (IPv4 or IPv6)
    AEA_ACTIVE_DATE: date


# ============================================================================
# Connection & Session Models
# ============================================================================

@dataclass
class Connection:
    """CONNECTIONS table - EPP connection log"""
    CNN_ID: int
    CNN_ACCOUNT_ID: int  # FK to ACCOUNTS
    CNN_USER_ID: int  # FK to USERS
    CNN_SERVER_NAME: str
    CNN_SERVER_IP: str
    CNN_SERVER_PORT: int
    CNN_CLIENT_IP: str  # Client IP (IMPORTANT!)
    CNN_CLIENT_PORT: int
    CNN_START_TIME: datetime
    CNN_LOGIN_FAILURES: int = 0
    CNN_STATUS: str = "OPEN"  # Connection status
    CNN_END_TIME: Optional[datetime] = None
    CNN_END_REASON: Optional[str] = None


@dataclass
class Session:
    """SESSIONS table - EPP session log"""
    SES_ID: int
    SES_START_TIME: datetime
    SES_LAST_USED: datetime
    SES_STATUS: str = "OPEN"  # Session status
    SES_LANG: str = "en"
    SES_USER_ID: Optional[int] = None  # FK to USERS
    SES_CONNECTION_ID: Optional[int] = None  # FK to CONNECTIONS
    SES_CLIENT_IP: Optional[str] = None
    SES_END_TIME: Optional[datetime] = None
    SES_END_REASON: Optional[str] = None
    SES_OBJECT_URIS: Optional[str] = None  # Comma-separated URIs
    SES_EXTENSION_URIS: Optional[str] = None


@dataclass
class Transaction:
    """TRANSACTIONS table - EPP command log"""
    TRN_ID: int
    TRN_COMMAND: str  # Command name
    TRN_START_TIME: datetime
    TRN_CONNECTION_ID: Optional[int] = None  # FK to CONNECTIONS
    TRN_SESSION_ID: Optional[int] = None  # FK to SESSIONS
    TRN_ACCOUNT_ID: Optional[int] = None  # FK to ACCOUNTS
    TRN_USER_ID: Optional[int] = None  # FK to USERS
    TRN_CLIENT_REF: Optional[str] = None  # Client transaction ID (clTRID)
    TRN_ROID: Optional[str] = None  # Affected object ROID
    TRN_END_TIME: Optional[datetime] = None
    TRN_RESPONSE_CODE: Optional[int] = None  # EPP response code
    TRN_RESPONSE_MESSAGE: Optional[str] = None
    TRN_AMOUNT: Optional[Decimal] = None  # Transaction amount
    TRN_BALANCE: Optional[Decimal] = None  # Balance after
    TRN_AUDIT_LOG: Optional[str] = None  # Audit details
    TRN_APPLICATION_TIME: Optional[int] = None  # Processing time (ms)


# ============================================================================
# Registry Object Models
# ============================================================================

@dataclass
class RegistryObject:
    """REGISTRY_OBJECTS table - Base object table"""
    OBJ_ROID: str  # Primary Key (Registry Object ID)
    OBJ_TYPE: str  # domain/contact/host
    OBJ_STATUS: str  # Current status
    OBJ_CREATE_DATE: date
    OBJ_CREATE_USER_ID: int  # FK to creating user
    OBJ_MANAGE_ACCOUNT_ID: int  # FK to managing account (registrar)
    OBJ_LOCKED: str = "N"  # Locked flag Y/N
    OBJ_PASSWORD: Optional[str] = None  # Auth info password
    OBJ_UPDATE_DATE: Optional[date] = None
    OBJ_UPDATE_USER_ID: Optional[int] = None  # FK to updating user
    OBJ_TRANSFER_DATE: Optional[date] = None
    OBJ_DELETE_DATE: Optional[date] = None


# ============================================================================
# Domain Models
# ============================================================================

@dataclass
class Domain:
    """DOMAINS table - Domain data"""
    DOM_ROID: str  # Primary Key, FK to REGISTRY_OBJECTS
    DOM_NAME: str  # Full domain name
    DOM_LABEL: str  # Domain label (without TLD)
    DOM_CANONICAL_FORM: str  # Canonical form
    DOM_ZONE: str  # FK to ZONES
    DOM_REGISTRANT_ROID: str  # FK to registrant contact
    DOM_DNS_QUALIFIED: str = "N"  # Y/N
    DOM_DNS_HOLD: str = "N"  # Y/N
    DOM_ACTIVE_INDICATOR: str = ""
    DOM_REGISTRATION_ID: Optional[int] = None  # FK to DOMAIN_REGISTRATIONS


@dataclass
class DomainRegistration:
    """DOMAIN_REGISTRATIONS table - Registration periods"""
    DRE_ID: int  # Primary Key
    DRE_ROID: str  # FK to DOMAINS
    DRE_SEQ: int  # Registration sequence
    DRE_PERIOD: int  # Registration period
    DRE_UNIT: str  # y=year, m=month
    DRE_STATUS: str  # Status
    DRE_REQUEST_DATE: date
    DRE_START_DATE: Optional[date] = None
    DRE_EXPIRE_DATE: Optional[date] = None


@dataclass
class DomainContact:
    """DOMAIN_CONTACTS table - Domain contact associations"""
    DCN_DOMAIN_ROID: str  # FK to DOMAINS
    DCN_CONTACT_ROID: str  # FK to CONTACTS
    DCN_TYPE: str  # admin/tech/billing


@dataclass
class DomainNameserver:
    """DOMAIN_NAMESERVERS table - Domain nameserver associations"""
    DNS_DOMAIN_ROID: str  # FK to DOMAINS
    DNS_HOST_ROID: str  # FK to HOSTS


# ============================================================================
# Contact Models
# ============================================================================

@dataclass
class Contact:
    """CONTACTS table - Contact data"""
    CON_ROID: str  # Primary Key, FK to REGISTRY_OBJECTS
    CON_UID: str  # User-assigned contact ID
    CON_EMAIL: str
    CON_NAME: Optional[str] = None
    CON_ORG: Optional[str] = None
    CON_STREET1: Optional[str] = None
    CON_STREET2: Optional[str] = None
    CON_STREET3: Optional[str] = None
    CON_CITY: Optional[str] = None
    CON_STATE: Optional[str] = None
    CON_POSTCODE: Optional[str] = None
    CON_COUNTRY: Optional[str] = None  # ISO 3166
    CON_PHONE: Optional[str] = None
    CON_PHONE_EXT: Optional[str] = None
    CON_FAX: Optional[str] = None
    CON_FAX_EXT: Optional[str] = None


# ============================================================================
# Host Models
# ============================================================================

@dataclass
class Host:
    """HOSTS table - Host/nameserver data"""
    HOS_ROID: str  # Primary Key, FK to REGISTRY_OBJECTS
    HOS_NAME: str  # Host FQDN
    HOS_USERFORM: str  # User form
    HOS_ACTIVE_INDICATOR: str = ""
    HOS_DOMAIN_ROID: Optional[str] = None  # FK to parent domain (subordinate)


@dataclass
class HostAddress:
    """HOST_ADDRESSES table - Host IP addresses"""
    HAD_ROID: str  # FK to HOSTS
    HAD_ADDRESS: str  # IP address
    HAD_TYPE: str  # v4/v6


# ============================================================================
# Status Models
# ============================================================================

@dataclass
class EPPDomainStatus:
    """EPP_DOMAIN_STATUSES table"""
    EDS_ROID: str  # FK to DOMAINS
    EDS_STATUS: str  # EPP status code
    EDS_LANG: Optional[str] = None
    EDS_REASON: Optional[str] = None


@dataclass
class EPPContactStatus:
    """EPP_CONTACT_STATUSES table"""
    ECS_ROID: str  # FK to CONTACTS
    ECS_STATUS: str  # EPP status code
    ECS_LANG: Optional[str] = None
    ECS_REASON: Optional[str] = None


@dataclass
class EPPHostStatus:
    """EPP_HOST_STATUSES table"""
    EHS_ROID: str  # FK to HOSTS
    EHS_STATUS: str  # EPP status code
    EHS_LANG: Optional[str] = None
    EHS_REASON: Optional[str] = None


# ============================================================================
# Zone & Pricing Models
# ============================================================================

@dataclass
class Zone:
    """ZONES table - TLD configuration"""
    ZON_ZONE: str  # Primary Key (e.g., "ae", "com.ae")
    ZON_ID: int  # Unique ID
    ZON_STATUS: str  # Status
    ZON_FORMAT: str  # Regex for domain validation
    ZON_CREATE_MIN_YEARS: int
    ZON_CREATE_MAX_YEARS: int
    ZON_MAX_EXPIRY_YEARS: int
    ZON_TRANSFER_PENDING_DAYS: int
    ZON_DELETE_CANCEL_DAYS: int
    ZON_RENEW_BEFORE_EXPIRE_DAYS: int
    ZON_MIN_DNS_TO_DELEGATE: int


@dataclass
class Rate:
    """RATES table - Pricing"""
    RAT_ID: int  # Primary Key
    RAT_ZONE: str  # FK to ZONES
    RAT_PERIOD: int  # Period
    RAT_UNIT: str  # y/m
    RAT_AMOUNT: Decimal  # Price
    RAT_CURRENCY: str  # Currency code
    RAT_START_DATE: date
    RAT_END_DATE: Optional[date] = None


# ============================================================================
# Transfer Models
# ============================================================================

@dataclass
class Transfer:
    """TRANSFERS table - Transfer records"""
    TRX_ID: int  # Primary Key
    TRX_ROID: str  # FK to REGISTRY_OBJECTS
    TRX_STATUS: str  # Transfer status
    TRX_REQUEST_DATE: date
    TRX_REQUEST_USER_ID: int  # FK to requesting user
    TRX_TO_ACCOUNT_ID: int  # FK to gaining account
    TRX_FROM_ACCOUNT_ID: int  # FK to losing account
    TRX_ACCEPT_DATE: date  # Auto-accept date
    TRX_ACTION_DATE: Optional[date] = None
    TRX_PERIOD: Optional[int] = None  # Renewal period
    TRX_UNIT: Optional[str] = None  # Period unit


# ============================================================================
# Composite/View Models (for query results)
# ============================================================================

@dataclass
class DomainInfo:
    """Composite domain information for EPP info response"""
    name: str
    roid: str
    statuses: List[dict] = field(default_factory=list)
    registrant: Optional[str] = None
    contacts: List[dict] = field(default_factory=list)  # [{id, type}]
    nameservers: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)  # Subordinate hosts
    clID: str = ""  # Sponsoring client
    crID: Optional[str] = None  # Creator
    crDate: Optional[str] = None
    upID: Optional[str] = None  # Updater
    upDate: Optional[str] = None
    exDate: Optional[str] = None  # Expiry
    trDate: Optional[str] = None  # Transfer
    authInfo: Optional[str] = None


@dataclass
class ContactInfo:
    """Composite contact information for EPP info response"""
    id: str
    roid: str
    statuses: List[dict] = field(default_factory=list)
    postalInfo_int: Optional[dict] = None
    postalInfo_loc: Optional[dict] = None
    voice: Optional[str] = None
    voice_ext: Optional[str] = None
    fax: Optional[str] = None
    fax_ext: Optional[str] = None
    email: str = ""
    clID: str = ""
    crID: Optional[str] = None
    crDate: Optional[str] = None
    upID: Optional[str] = None
    upDate: Optional[str] = None
    authInfo: Optional[str] = None


@dataclass
class HostInfo:
    """Composite host information for EPP info response"""
    name: str
    roid: str
    statuses: List[dict] = field(default_factory=list)
    addrs: List[dict] = field(default_factory=list)  # [{addr, ip}]
    clID: str = ""
    crID: Optional[str] = None
    crDate: Optional[str] = None
    upID: Optional[str] = None
    upDate: Optional[str] = None
