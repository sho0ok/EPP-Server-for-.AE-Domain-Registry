"""
EPP Input Validator

Validates all EPP input parameters against RFC specifications and registry policy.
"""

import re
import logging
from typing import Any, Dict, List, Optional, Tuple
from ipaddress import ip_address, IPv4Address, IPv6Address

logger = logging.getLogger("epp.validators")


class ValidationError(Exception):
    """Validation error with EPP code."""

    def __init__(
        self,
        message: str,
        code: int = 2005,
        value: Optional[str] = None
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.value = value


class EPPValidator:
    """
    Validates EPP input parameters.

    Provides validation for:
    - Domain names
    - Contact IDs
    - Host names
    - IP addresses
    - Email addresses
    - Phone numbers
    - Country codes
    - Postal codes
    """

    # Domain name pattern (simplified - zone validation done separately)
    DOMAIN_LABEL_PATTERN = re.compile(
        r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$',
        re.IGNORECASE
    )

    # Contact ID pattern (alphanumeric with limited special chars)
    CONTACT_ID_PATTERN = re.compile(
        r'^[a-zA-Z0-9][\w\-]{2,15}$'
    )

    # Email pattern (RFC 5322 simplified)
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )

    # Phone pattern (E.164 format: +CC.NUMBER with optional extension)
    PHONE_PATTERN = re.compile(
        r'^\+[0-9]{1,3}\.[0-9]{1,14}$'
    )

    # ISO 3166-1 alpha-2 country codes (subset - should be complete list)
    COUNTRY_CODES = {
        'AE', 'AF', 'AL', 'AM', 'AO', 'AR', 'AT', 'AU', 'AZ', 'BA', 'BD', 'BE',
        'BG', 'BH', 'BN', 'BO', 'BR', 'BY', 'CA', 'CH', 'CL', 'CN', 'CO', 'CR',
        'CY', 'CZ', 'DE', 'DK', 'DO', 'DZ', 'EC', 'EE', 'EG', 'ES', 'FI', 'FR',
        'GB', 'GE', 'GH', 'GR', 'GT', 'HK', 'HN', 'HR', 'HU', 'ID', 'IE', 'IL',
        'IN', 'IQ', 'IR', 'IS', 'IT', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KR',
        'KW', 'KZ', 'LB', 'LK', 'LT', 'LU', 'LV', 'LY', 'MA', 'MD', 'ME', 'MK',
        'MM', 'MN', 'MO', 'MT', 'MU', 'MV', 'MX', 'MY', 'NG', 'NI', 'NL', 'NO',
        'NP', 'NZ', 'OM', 'PA', 'PE', 'PH', 'PK', 'PL', 'PR', 'PS', 'PT', 'PY',
        'QA', 'RO', 'RS', 'RU', 'SA', 'SD', 'SE', 'SG', 'SI', 'SK', 'SN', 'SV',
        'SY', 'TH', 'TN', 'TR', 'TW', 'TZ', 'UA', 'UG', 'US', 'UY', 'UZ', 'VE',
        'VN', 'YE', 'ZA', 'ZM', 'ZW'
    }

    # EPP status values
    DOMAIN_STATUSES = {
        'clientDeleteProhibited', 'clientHold', 'clientRenewProhibited',
        'clientTransferProhibited', 'clientUpdateProhibited',
        'serverDeleteProhibited', 'serverHold', 'serverRenewProhibited',
        'serverTransferProhibited', 'serverUpdateProhibited',
        'ok', 'pendingCreate', 'pendingDelete', 'pendingRenew',
        'pendingTransfer', 'pendingUpdate'
    }

    CONTACT_STATUSES = {
        'clientDeleteProhibited', 'clientTransferProhibited',
        'clientUpdateProhibited', 'serverDeleteProhibited',
        'serverTransferProhibited', 'serverUpdateProhibited',
        'ok', 'pendingCreate', 'pendingDelete', 'pendingTransfer',
        'pendingUpdate', 'linked'
    }

    HOST_STATUSES = {
        'clientDeleteProhibited', 'clientUpdateProhibited',
        'serverDeleteProhibited', 'serverUpdateProhibited',
        'ok', 'pendingCreate', 'pendingDelete', 'pendingTransfer',
        'pendingUpdate', 'linked'
    }

    def validate_domain_name(
        self,
        name: str,
        zone_format: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate domain name format.

        Args:
            name: Domain name to validate
            zone_format: Optional regex pattern from zone config

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not name:
            return False, "Domain name is required"

        name = name.lower()

        # Check total length
        if len(name) > 253:
            return False, "Domain name exceeds maximum length of 253 characters"

        # Split into labels
        labels = name.split(".")
        if len(labels) < 2:
            return False, "Domain name must have at least two labels"

        # Validate each label
        for label in labels:
            if not label:
                return False, "Domain name contains empty label"

            if len(label) > 63:
                return False, f"Label '{label}' exceeds maximum length of 63 characters"

            if not self.DOMAIN_LABEL_PATTERN.match(label):
                return False, f"Label '{label}' contains invalid characters"

            # Check for double hyphens (except IDN prefix)
            if "--" in label and not label.startswith("xn--"):
                return False, f"Label '{label}' contains consecutive hyphens"

        # Check against zone format if provided
        if zone_format:
            try:
                if not re.match(zone_format, name):
                    return False, "Domain name does not match zone format"
            except re.error:
                logger.warning(f"Invalid zone format regex: {zone_format}")

        return True, None

    def validate_contact_id(self, contact_id: str) -> Tuple[bool, Optional[str]]:
        """
        Validate contact ID format.

        Args:
            contact_id: Contact ID to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not contact_id:
            return False, "Contact ID is required"

        if len(contact_id) < 3:
            return False, "Contact ID must be at least 3 characters"

        if len(contact_id) > 16:
            return False, "Contact ID must be at most 16 characters"

        if not self.CONTACT_ID_PATTERN.match(contact_id):
            return False, "Contact ID contains invalid characters"

        return True, None

    def validate_host_name(self, hostname: str) -> Tuple[bool, Optional[str]]:
        """
        Validate hostname format.

        Args:
            hostname: Hostname to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not hostname:
            return False, "Hostname is required"

        hostname = hostname.lower()

        # Check total length
        if len(hostname) > 253:
            return False, "Hostname exceeds maximum length of 253 characters"

        # Split into labels
        labels = hostname.split(".")
        if len(labels) < 2:
            return False, "Hostname must have at least two labels"

        # Validate each label
        for label in labels:
            if not label:
                return False, "Hostname contains empty label"

            if len(label) > 63:
                return False, f"Label '{label}' exceeds maximum length"

            if not self.DOMAIN_LABEL_PATTERN.match(label):
                return False, f"Label '{label}' contains invalid characters"

        return True, None

    def validate_ip_address(
        self,
        addr: str,
        ip_version: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate IP address.

        Args:
            addr: IP address to validate
            ip_version: Expected version ('v4' or 'v6'), or None for any

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not addr:
            return False, "IP address is required"

        try:
            ip = ip_address(addr)

            if ip_version == "v4" and not isinstance(ip, IPv4Address):
                return False, "Expected IPv4 address"

            if ip_version == "v6" and not isinstance(ip, IPv6Address):
                return False, "Expected IPv6 address"

            # Check for reserved addresses
            if ip.is_loopback:
                return False, "Loopback addresses are not allowed"

            if ip.is_multicast:
                return False, "Multicast addresses are not allowed"

            if ip.is_unspecified:
                return False, "Unspecified addresses are not allowed"

            return True, None

        except ValueError as e:
            return False, f"Invalid IP address: {e}"

    def validate_email(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Validate email address.

        Args:
            email: Email address to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not email:
            return False, "Email address is required"

        if len(email) > 255:
            return False, "Email address exceeds maximum length"

        if not self.EMAIL_PATTERN.match(email):
            return False, "Invalid email address format"

        return True, None

    def validate_phone(
        self,
        phone: str,
        extension: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate phone number in E.164 format.

        Args:
            phone: Phone number (+CC.NUMBER format)
            extension: Optional extension

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not phone:
            return True, None  # Phone is optional

        if len(phone) > 17:
            return False, "Phone number exceeds maximum length"

        if not self.PHONE_PATTERN.match(phone):
            return False, "Phone must be in E.164 format (+CC.NUMBER)"

        if extension and len(extension) > 17:
            return False, "Phone extension exceeds maximum length"

        return True, None

    def validate_country_code(self, code: str) -> Tuple[bool, Optional[str]]:
        """
        Validate ISO 3166-1 alpha-2 country code.

        Args:
            code: Country code to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not code:
            return False, "Country code is required"

        code = code.upper()

        if len(code) != 2:
            return False, "Country code must be 2 characters"

        if code not in self.COUNTRY_CODES:
            return False, f"Invalid country code: {code}"

        return True, None

    def validate_postal_code(
        self,
        postal_code: str,
        country_code: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate postal code.

        Args:
            postal_code: Postal code to validate
            country_code: Optional country for format validation

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not postal_code:
            return True, None  # Postal code is optional

        if len(postal_code) > 16:
            return False, "Postal code exceeds maximum length"

        # Basic alphanumeric check
        if not re.match(r'^[\w\s\-]+$', postal_code):
            return False, "Postal code contains invalid characters"

        return True, None

    def validate_status(
        self,
        status: str,
        object_type: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate EPP status value.

        Args:
            status: Status value to validate
            object_type: Object type (domain, contact, host)

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not status:
            return False, "Status is required"

        valid_statuses = {
            "domain": self.DOMAIN_STATUSES,
            "contact": self.CONTACT_STATUSES,
            "host": self.HOST_STATUSES
        }.get(object_type, set())

        if status not in valid_statuses:
            return False, f"Invalid {object_type} status: {status}"

        return True, None

    def validate_period(
        self,
        period: int,
        unit: str,
        min_years: int = 1,
        max_years: int = 10
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate registration/renewal period.

        Args:
            period: Period value
            unit: Period unit ('y' for years, 'm' for months)
            min_years: Minimum years allowed
            max_years: Maximum years allowed

        Returns:
            Tuple of (is_valid, error_message)
        """
        if unit not in ('y', 'm'):
            return False, "Period unit must be 'y' (years) or 'm' (months)"

        # Convert to years for comparison
        years = period if unit == 'y' else period / 12

        if years < min_years:
            return False, f"Period must be at least {min_years} year(s)"

        if years > max_years:
            return False, f"Period must be at most {max_years} year(s)"

        return True, None

    def validate_contact_data(self, data: Dict[str, Any]) -> List[str]:
        """
        Validate complete contact data.

        Args:
            data: Contact data dictionary

        Returns:
            List of error messages (empty if valid)
        """
        errors = []

        # Contact ID
        if "id" in data:
            valid, error = self.validate_contact_id(data["id"])
            if not valid:
                errors.append(error)

        # Email (required)
        if "email" in data:
            valid, error = self.validate_email(data["email"])
            if not valid:
                errors.append(error)
        else:
            errors.append("Email is required")

        # Phone
        if "voice" in data:
            valid, error = self.validate_phone(data["voice"], data.get("voice_ext"))
            if not valid:
                errors.append(f"Voice: {error}")

        # Fax
        if "fax" in data:
            valid, error = self.validate_phone(data["fax"], data.get("fax_ext"))
            if not valid:
                errors.append(f"Fax: {error}")

        # Postal info
        for ptype in ["postalInfo_int", "postalInfo_loc"]:
            postal = data.get(ptype)
            if postal:
                if postal.get("cc"):
                    valid, error = self.validate_country_code(postal["cc"])
                    if not valid:
                        errors.append(f"{ptype}: {error}")

                if postal.get("pc"):
                    valid, error = self.validate_postal_code(
                        postal["pc"], postal.get("cc")
                    )
                    if not valid:
                        errors.append(f"{ptype}: {error}")

        return errors


# Global validator instance
_validator: Optional[EPPValidator] = None


def get_validator() -> EPPValidator:
    """Get or create global validator instance."""
    global _validator
    if _validator is None:
        _validator = EPPValidator()
    return _validator


# Convenience functions
def validate_domain_name(
    name: str,
    zone_format: Optional[str] = None
) -> Tuple[bool, Optional[str]]:
    """Validate domain name."""
    return get_validator().validate_domain_name(name, zone_format)


def validate_contact_id(contact_id: str) -> Tuple[bool, Optional[str]]:
    """Validate contact ID."""
    return get_validator().validate_contact_id(contact_id)


def validate_host_name(hostname: str) -> Tuple[bool, Optional[str]]:
    """Validate hostname."""
    return get_validator().validate_host_name(hostname)


def validate_ip_address(
    addr: str,
    ip_version: Optional[str] = None
) -> Tuple[bool, Optional[str]]:
    """Validate IP address."""
    return get_validator().validate_ip_address(addr, ip_version)


def validate_email(email: str) -> Tuple[bool, Optional[str]]:
    """Validate email address."""
    return get_validator().validate_email(email)
