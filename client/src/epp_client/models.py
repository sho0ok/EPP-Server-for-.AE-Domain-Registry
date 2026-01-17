"""
EPP Client Models

Data classes for EPP requests and responses.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Union


# =============================================================================
# Common Models
# =============================================================================

@dataclass
class StatusValue:
    """Status with optional comment/reason.

    Per RFC 5731, status can include an optional description text.
    Example: clientHold with reason "Payment pending"
    """
    status: str
    reason: Optional[str] = None
    lang: str = "en"


# =============================================================================
# Response Models
# =============================================================================

@dataclass
class Greeting:
    """EPP server greeting."""
    server_id: str
    server_date: datetime
    version: List[str] = field(default_factory=list)
    lang: List[str] = field(default_factory=list)
    obj_uris: List[str] = field(default_factory=list)
    ext_uris: List[str] = field(default_factory=list)
    dcp: Optional[Dict[str, Any]] = None  # Data Collection Policy


@dataclass
class EPPResponse:
    """Generic EPP response."""
    code: int
    message: str
    cl_trid: Optional[str] = None
    sv_trid: Optional[str] = None
    data: Any = None
    raw_xml: Optional[str] = None

    @property
    def success(self) -> bool:
        """Check if response indicates success."""
        return 1000 <= self.code < 2000


# -----------------------------------------------------------------------------
# Domain Response Models
# -----------------------------------------------------------------------------

@dataclass
class DomainCheckItem:
    """Single domain check result."""
    name: str
    available: bool
    reason: Optional[str] = None


@dataclass
class DomainCheckResult:
    """Domain check response."""
    results: List[DomainCheckItem] = field(default_factory=list)

    def is_available(self, name: str) -> bool:
        """Check if specific domain is available."""
        for item in self.results:
            if item.name.lower() == name.lower():
                return item.available
        return False


@dataclass
class DomainContact:
    """Domain contact association."""
    id: str
    type: str  # admin, tech, billing


@dataclass
class DomainEligibilityInfo:
    """AE Eligibility info from domain response."""
    eligibility_type: Optional[str] = None
    eligibility_name: Optional[str] = None
    eligibility_id: Optional[str] = None
    eligibility_id_type: Optional[str] = None
    policy_reason: Optional[int] = None
    registrant_id: Optional[str] = None
    registrant_id_type: Optional[str] = None
    registrant_name: Optional[str] = None


@dataclass
class DomainInfo:
    """Domain info response."""
    name: str
    roid: str
    status: List[str] = field(default_factory=list)
    registrant: Optional[str] = None
    contacts: List[DomainContact] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)  # Subordinate hosts
    cl_id: str = ""  # Sponsoring client
    cr_id: Optional[str] = None  # Creator
    cr_date: Optional[datetime] = None
    up_id: Optional[str] = None  # Updater
    up_date: Optional[datetime] = None
    ex_date: Optional[datetime] = None  # Expiry
    tr_date: Optional[datetime] = None  # Transfer
    auth_info: Optional[str] = None
    # Extension data for restricted zones
    eligibility: Optional[DomainEligibilityInfo] = None


@dataclass
class DomainCreateResult:
    """Domain create response."""
    name: str
    cr_date: datetime
    ex_date: Optional[datetime] = None


@dataclass
class DomainRenewResult:
    """Domain renew response."""
    name: str
    ex_date: datetime


@dataclass
class DomainTransferResult:
    """Domain transfer response."""
    name: str
    tr_status: str
    re_id: str  # Requesting registrar
    re_date: datetime
    ac_id: str  # Acting registrar
    ac_date: datetime
    ex_date: Optional[datetime] = None


# -----------------------------------------------------------------------------
# Contact Response Models
# -----------------------------------------------------------------------------

@dataclass
class ContactCheckItem:
    """Single contact check result."""
    id: str
    available: bool
    reason: Optional[str] = None


@dataclass
class ContactCheckResult:
    """Contact check response."""
    results: List[ContactCheckItem] = field(default_factory=list)

    def is_available(self, id: str) -> bool:
        """Check if specific contact ID is available."""
        for item in self.results:
            if item.id == id:
                return item.available
        return False


@dataclass
class PostalInfoData:
    """Contact postal information."""
    type: str  # int or loc
    name: Optional[str] = None
    org: Optional[str] = None
    street: List[str] = field(default_factory=list)
    city: Optional[str] = None
    sp: Optional[str] = None  # State/Province
    pc: Optional[str] = None  # Postal Code
    cc: Optional[str] = None  # Country Code


@dataclass
class ContactInfo:
    """Contact info response."""
    id: str
    roid: str
    status: List[str] = field(default_factory=list)
    postal_info: List[PostalInfoData] = field(default_factory=list)
    voice: Optional[str] = None
    voice_ext: Optional[str] = None
    fax: Optional[str] = None
    fax_ext: Optional[str] = None
    email: Optional[str] = None
    cl_id: str = ""
    cr_id: Optional[str] = None
    cr_date: Optional[datetime] = None
    up_id: Optional[str] = None
    up_date: Optional[datetime] = None
    tr_date: Optional[datetime] = None
    auth_info: Optional[str] = None
    disclose: Optional[Dict[str, bool]] = None


@dataclass
class ContactCreateResult:
    """Contact create response."""
    id: str
    cr_date: datetime


# -----------------------------------------------------------------------------
# Host Response Models
# -----------------------------------------------------------------------------

@dataclass
class HostCheckItem:
    """Single host check result."""
    name: str
    available: bool
    reason: Optional[str] = None


@dataclass
class HostCheckResult:
    """Host check response."""
    results: List[HostCheckItem] = field(default_factory=list)

    def is_available(self, name: str) -> bool:
        """Check if specific host is available."""
        for item in self.results:
            if item.name.lower() == name.lower():
                return item.available
        return False


@dataclass
class HostAddress:
    """Host IP address."""
    address: str
    ip_version: str = "v4"  # v4 or v6


@dataclass
class HostInfo:
    """Host info response."""
    name: str
    roid: str
    status: List[str] = field(default_factory=list)
    addresses: List[HostAddress] = field(default_factory=list)
    cl_id: str = ""
    cr_id: Optional[str] = None
    cr_date: Optional[datetime] = None
    up_id: Optional[str] = None
    up_date: Optional[datetime] = None
    tr_date: Optional[datetime] = None


@dataclass
class HostCreateResult:
    """Host create response."""
    name: str
    cr_date: datetime


# -----------------------------------------------------------------------------
# Poll Response Models
# -----------------------------------------------------------------------------

@dataclass
class PollMessage:
    """Poll message."""
    id: str
    count: int
    qdate: datetime
    message: str
    data: Any = None


# =============================================================================
# Request Models
# =============================================================================

@dataclass
class PostalInfo:
    """Contact postal information for create/update."""
    name: str
    city: str
    cc: str  # Country code (2-letter ISO)
    type: str = "int"  # int or loc
    org: Optional[str] = None
    street: List[str] = field(default_factory=list)
    sp: Optional[str] = None  # State/Province
    pc: Optional[str] = None  # Postal Code


@dataclass
class AEEligibility:
    """AE Eligibility extension data for restricted zones (.co.ae, .gov.ae, etc.)."""
    eligibility_type: str  # TradeLicense, Trademark, etc.
    eligibility_name: str  # Company/organization name
    eligibility_id: Optional[str] = None  # License/trademark number
    eligibility_id_type: Optional[str] = None  # TradeLicense, Trademark, etc.
    policy_reason: Optional[int] = None  # 1-3 for different policy reasons
    registrant_id: Optional[str] = None  # Emirates ID, etc.
    registrant_id_type: Optional[str] = None  # EmiratesID, Passport, etc.
    registrant_name: Optional[str] = None  # Registrant name


@dataclass
class DomainCreate:
    """Domain create request."""
    name: str
    registrant: str
    period: int = 1
    period_unit: str = "y"  # y=year, m=month
    admin: Optional[str] = None
    tech: Optional[str] = None
    billing: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    auth_info: Optional[str] = None  # Auto-generated if not provided
    # Extension for restricted zones
    ae_eligibility: Optional[AEEligibility] = None


@dataclass
class DomainUpdate:
    """Domain update request.

    Status can be specified as:
    - Simple string: "clientHold"
    - StatusValue with reason: StatusValue("clientHold", "Payment pending")
    """
    name: str
    add_status: List[Union[str, StatusValue]] = field(default_factory=list)
    rem_status: List[Union[str, StatusValue]] = field(default_factory=list)
    add_ns: List[str] = field(default_factory=list)
    rem_ns: List[str] = field(default_factory=list)
    add_contacts: List[DomainContact] = field(default_factory=list)
    rem_contacts: List[DomainContact] = field(default_factory=list)
    new_registrant: Optional[str] = None
    new_auth_info: Optional[str] = None


@dataclass
class ContactCreate:
    """Contact create request."""
    id: str
    email: str
    postal_info: PostalInfo
    voice: Optional[str] = None
    voice_ext: Optional[str] = None
    fax: Optional[str] = None
    fax_ext: Optional[str] = None
    auth_info: Optional[str] = None  # Auto-generated if not provided
    disclose: Optional[Dict[str, bool]] = None


@dataclass
class ContactUpdate:
    """Contact update request."""
    id: str
    add_status: List[str] = field(default_factory=list)
    rem_status: List[str] = field(default_factory=list)
    new_postal_info: Optional[PostalInfo] = None
    new_voice: Optional[str] = None
    new_fax: Optional[str] = None
    new_email: Optional[str] = None
    new_auth_info: Optional[str] = None


@dataclass
class HostCreate:
    """Host create request."""
    name: str
    addresses: List[HostAddress] = field(default_factory=list)


@dataclass
class HostUpdate:
    """Host update request."""
    name: str
    add_addresses: List[HostAddress] = field(default_factory=list)
    rem_addresses: List[HostAddress] = field(default_factory=list)
    add_status: List[str] = field(default_factory=list)
    rem_status: List[str] = field(default_factory=list)
    new_name: Optional[str] = None
