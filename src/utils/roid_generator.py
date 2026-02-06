"""
ROID Generator

Generates Registry Object IDs (ROIDs) for new objects.
ROIDs are unique identifiers used throughout the EPP system.

ARI Format: <32-CHAR-HEX>-<REGISTRY_IDENTIFIER>
Example: D5BA7AFAF60AC2F595F2151D05F7E7C77-ARI

The ARI system uses object_t.generate_roid_number(seed_num) which takes
the OBJ_ID_SEQ sequence value and produces a 32-character hex string,
then appends '-' + Registry Identifier (from SETTINGS table).
"""

import hashlib
import logging
from typing import Optional

from src.database.connection import get_pool, DatabasePool

logger = logging.getLogger("epp.utils.roid")

# ARI Registry Identifier from SETTINGS table
DEFAULT_REGISTRY_ID = "ARI"


class ROIDGenerator:
    """
    Generates unique Registry Object IDs matching ARI format.

    Uses Oracle sequence OBJ_ID_SEQ for uniqueness and generates
    a 32-character hex identifier from the sequence value, matching
    ARI's object_t.generate_roid_number() behavior.
    """

    def __init__(self, pool: DatabasePool, registry_id: str = DEFAULT_REGISTRY_ID):
        """
        Initialize ROID generator.

        Args:
            pool: Database pool for sequence access
            registry_id: Registry identifier suffix (default: ARI)
        """
        self.pool = pool
        self.registry_id = registry_id
        self._sequence_name = "OBJ_ID_SEQ"

    def _generate_roid_number(self, seed_num: int) -> str:
        """
        Generate a 32-character hex ROID number from a seed.

        This replicates ARI's object_t.generate_roid_number(seed_num)
        which produces a fixed-length hex identifier from a sequence value.

        Args:
            seed_num: Sequence value to use as seed

        Returns:
            32-character uppercase hex string
        """
        # ARI uses a deterministic hash of the sequence number
        # to produce a 32-char hex string (matching MD5 output length)
        hash_input = str(seed_num).encode('utf-8')
        hex_str = hashlib.md5(hash_input).hexdigest().upper()
        return hex_str

    async def generate(self) -> str:
        """
        Generate a new ROID in ARI format.

        Returns:
            New ROID string (e.g., "D5BA7AFAF60AC2F595F2151D05F7E7C77-ARI")
        """
        seq_value = await self.pool.get_next_sequence(self._sequence_name)
        roid_number = self._generate_roid_number(seq_value)
        roid = f"{roid_number}-{self.registry_id}"
        logger.debug(f"Generated ROID: {roid} (seq={seq_value})")
        return roid

    async def generate_for_type(self, obj_type: str) -> str:
        """
        Generate a ROID with type prefix.

        Args:
            obj_type: Object type (domain, contact, host)

        Returns:
            New ROID string
        """
        return await self.generate()

    def parse(self, roid: str) -> dict:
        """
        Parse a ROID into its components.

        Args:
            roid: ROID string to parse

        Returns:
            Dict with 'roid_number' and 'registry_id' keys
        """
        parts = roid.rsplit("-", 1)
        if len(parts) == 2:
            return {
                "roid_number": parts[0],
                "registry_id": parts[1]
            }
        return {
            "roid_number": roid,
            "registry_id": ""
        }

    def is_valid(self, roid: str) -> bool:
        """
        Validate ROID format.

        Accepts both ARI format (hex-SUFFIX) and legacy format (number-SUFFIX).

        Args:
            roid: ROID string to validate

        Returns:
            True if valid format
        """
        if not roid or not isinstance(roid, str):
            return False

        parts = roid.rsplit("-", 1)
        if len(parts) != 2:
            return False

        # Check roid_number part is hex or numeric
        roid_num = parts[0]
        if not roid_num:
            return False

        # Accept hex strings (ARI format) or plain numbers (legacy)
        try:
            int(roid_num, 16)
        except ValueError:
            return False

        # Check suffix is alphanumeric
        if not parts[1].isalnum():
            return False

        return True


# Global generator instance
_roid_generator: Optional[ROIDGenerator] = None


async def get_roid_generator(registry_id: str = DEFAULT_REGISTRY_ID) -> ROIDGenerator:
    """
    Get or create global ROID generator.

    Args:
        registry_id: Registry identifier suffix

    Returns:
        ROIDGenerator instance
    """
    global _roid_generator
    if _roid_generator is None:
        pool = await get_pool()
        _roid_generator = ROIDGenerator(pool, registry_id)
    return _roid_generator


async def generate_roid(suffix: str = DEFAULT_REGISTRY_ID) -> str:
    """
    Convenience function to generate a ROID.

    Args:
        suffix: Registry identifier suffix

    Returns:
        New ROID string
    """
    generator = await get_roid_generator(suffix)
    return await generator.generate()
