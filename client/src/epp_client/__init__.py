"""
EPP Client Toolkit

A production-ready Python EPP client for domain registrars.
Supports RFC 5730-5734 with TLS 1.2+.
"""

__version__ = "1.0.0"

from epp_client.client import EPPClient
from epp_client.async_client import AsyncEPPClient
from epp_client.pool import EPPConnectionPool, PoolConfig, create_pool
from epp_client.models import (
    AEEligibility,
    Greeting,
    EPPResponse,
    DomainCheckResult,
    DomainInfo,
    DomainEligibilityInfo,
    ContactCheckResult,
    ContactInfo,
    HostCheckResult,
    HostInfo,
    DomainCreate,
    ContactCreate,
    HostCreate,
    PostalInfo,
    StatusValue,
)
from epp_client.exceptions import (
    EPPError,
    EPPConnectionError,
    EPPAuthenticationError,
    EPPCommandError,
    EPPObjectNotFound,
    EPPObjectExists,
    EPPAuthorizationError,
    EPPParameterError,
)

__all__ = [
    # Clients
    "EPPClient",
    "AsyncEPPClient",
    # Pool
    "EPPConnectionPool",
    "PoolConfig",
    "create_pool",
    # Models
    "AEEligibility",
    "Greeting",
    "EPPResponse",
    "DomainCheckResult",
    "DomainInfo",
    "DomainEligibilityInfo",
    "ContactCheckResult",
    "ContactInfo",
    "HostCheckResult",
    "HostInfo",
    "DomainCreate",
    "ContactCreate",
    "HostCreate",
    "PostalInfo",
    "StatusValue",
    # Exceptions
    "EPPError",
    "EPPConnectionError",
    "EPPAuthenticationError",
    "EPPCommandError",
    "EPPObjectNotFound",
    "EPPObjectExists",
    "EPPAuthorizationError",
    "EPPParameterError",
]
