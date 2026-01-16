"""
Password Utilities

Handles auth info generation and validation for EPP objects.
Auth info is the password/authorization code used for transfers.
"""

import secrets
import string
import hashlib
import hmac
import logging
from typing import Optional

logger = logging.getLogger("epp.utils.password")

# Auth info configuration
AUTH_INFO_MIN_LENGTH = 8
AUTH_INFO_MAX_LENGTH = 32
AUTH_INFO_DEFAULT_LENGTH = 16

# Character set for generated auth info
# Excludes ambiguous characters (0, O, l, 1, I)
AUTH_INFO_CHARS = (
    string.ascii_uppercase.replace("O", "").replace("I", "") +
    string.ascii_lowercase.replace("l", "") +
    string.digits.replace("0", "").replace("1", "") +
    "!@#$%^&*"
)


def generate_auth_info(length: int = AUTH_INFO_DEFAULT_LENGTH) -> str:
    """
    Generate a random auth info string.

    Args:
        length: Length of auth info (default 16)

    Returns:
        Random auth info string
    """
    if length < AUTH_INFO_MIN_LENGTH:
        length = AUTH_INFO_MIN_LENGTH
    if length > AUTH_INFO_MAX_LENGTH:
        length = AUTH_INFO_MAX_LENGTH

    # Use secrets for cryptographic randomness
    auth_info = "".join(
        secrets.choice(AUTH_INFO_CHARS) for _ in range(length)
    )

    logger.debug(f"Generated auth info of length {length}")
    return auth_info


def validate_auth_info(auth_info: str) -> tuple[bool, Optional[str]]:
    """
    Validate auth info format.

    Args:
        auth_info: Auth info to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not auth_info:
        return False, "Auth info is required"

    if len(auth_info) < AUTH_INFO_MIN_LENGTH:
        return False, f"Auth info must be at least {AUTH_INFO_MIN_LENGTH} characters"

    if len(auth_info) > AUTH_INFO_MAX_LENGTH:
        return False, f"Auth info must be at most {AUTH_INFO_MAX_LENGTH} characters"

    # Check for printable ASCII characters
    for char in auth_info:
        if not (32 <= ord(char) <= 126):
            return False, "Auth info contains invalid characters"

    return True, None


def hash_auth_info(auth_info: str) -> str:
    """
    Hash auth info for storage.

    Note: For auth info, we typically store plain text in the ARI schema
    because it needs to be returned in EPP responses. This function is
    provided for implementations that want to hash.

    Args:
        auth_info: Plain text auth info

    Returns:
        Hashed auth info
    """
    return hashlib.sha256(auth_info.encode()).hexdigest()


def verify_auth_info(
    provided: str,
    stored: str,
    is_hashed: bool = False
) -> bool:
    """
    Verify auth info against stored value.

    Uses timing-safe comparison to prevent timing attacks.

    Args:
        provided: Auth info provided by user
        stored: Stored auth info
        is_hashed: Whether stored value is hashed

    Returns:
        True if auth info matches
    """
    if not provided or not stored:
        return False

    if is_hashed:
        provided_hash = hash_auth_info(provided)
        return hmac.compare_digest(provided_hash, stored)
    else:
        return hmac.compare_digest(provided, stored)


def mask_auth_info(auth_info: str, visible_chars: int = 4) -> str:
    """
    Mask auth info for logging/display.

    Args:
        auth_info: Auth info to mask
        visible_chars: Number of characters to show at end

    Returns:
        Masked auth info (e.g., "********abcd")
    """
    if not auth_info:
        return ""

    if len(auth_info) <= visible_chars:
        return "*" * len(auth_info)

    masked_length = len(auth_info) - visible_chars
    return "*" * masked_length + auth_info[-visible_chars:]


class AuthInfoPolicy:
    """
    Auth info policy configuration.

    Defines requirements for auth info strings.
    """

    def __init__(
        self,
        min_length: int = AUTH_INFO_MIN_LENGTH,
        max_length: int = AUTH_INFO_MAX_LENGTH,
        require_uppercase: bool = False,
        require_lowercase: bool = False,
        require_digit: bool = False,
        require_special: bool = False
    ):
        """
        Initialize auth info policy.

        Args:
            min_length: Minimum length
            max_length: Maximum length
            require_uppercase: Require uppercase letter
            require_lowercase: Require lowercase letter
            require_digit: Require digit
            require_special: Require special character
        """
        self.min_length = min_length
        self.max_length = max_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_special = require_special

    def validate(self, auth_info: str) -> tuple[bool, Optional[str]]:
        """
        Validate auth info against policy.

        Args:
            auth_info: Auth info to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Basic validation
        valid, error = validate_auth_info(auth_info)
        if not valid:
            return valid, error

        # Length checks
        if len(auth_info) < self.min_length:
            return False, f"Auth info must be at least {self.min_length} characters"

        if len(auth_info) > self.max_length:
            return False, f"Auth info must be at most {self.max_length} characters"

        # Character requirements
        if self.require_uppercase and not any(c.isupper() for c in auth_info):
            return False, "Auth info must contain at least one uppercase letter"

        if self.require_lowercase and not any(c.islower() for c in auth_info):
            return False, "Auth info must contain at least one lowercase letter"

        if self.require_digit and not any(c.isdigit() for c in auth_info):
            return False, "Auth info must contain at least one digit"

        if self.require_special:
            special_chars = set("!@#$%^&*()_+-=[]{}|;':\",./<>?")
            if not any(c in special_chars for c in auth_info):
                return False, "Auth info must contain at least one special character"

        return True, None


# Default policy instance
DEFAULT_POLICY = AuthInfoPolicy()


def validate_auth_info_policy(
    auth_info: str,
    policy: Optional[AuthInfoPolicy] = None
) -> tuple[bool, Optional[str]]:
    """
    Validate auth info against a policy.

    Args:
        auth_info: Auth info to validate
        policy: Policy to use (default: DEFAULT_POLICY)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if policy is None:
        policy = DEFAULT_POLICY
    return policy.validate(auth_info)
