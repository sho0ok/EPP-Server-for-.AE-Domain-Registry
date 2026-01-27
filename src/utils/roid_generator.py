"""
ROID Generator

Generates Registry Object IDs (ROIDs) for new objects.
ROIDs are unique identifiers used throughout the EPP system.

Format: <SEQUENCE>-<SUFFIX>
Example: 12345-AE
"""

import logging
from typing import Optional

from src.database.connection import get_pool, DatabasePool

logger = logging.getLogger("epp.utils.roid")


class ROIDGenerator:
    """
    Generates unique Registry Object IDs.

    Uses Oracle sequence OBJ_ROID_SEQ for uniqueness.
    """

    def __init__(self, pool: DatabasePool, suffix: str = "AE"):
        """
        Initialize ROID generator.

        Args:
            pool: Database pool for sequence access
            suffix: ROID suffix (default: AE)
        """
        self.pool = pool
        self.suffix = suffix
        self._sequence_name = "OBJ_ID_SEQ"

    async def generate(self) -> str:
        """
        Generate a new ROID.

        Returns:
            New ROID string (e.g., "12345-AE")
        """
        seq_value = await self.pool.get_next_sequence(self._sequence_name)
        roid = f"{seq_value}-{self.suffix}"
        logger.debug(f"Generated ROID: {roid}")
        return roid

    async def generate_for_type(self, obj_type: str) -> str:
        """
        Generate a ROID with type prefix.

        Some registries use type-specific prefixes.
        This implementation uses a simple format.

        Args:
            obj_type: Object type (domain, contact, host)

        Returns:
            New ROID string
        """
        # Standard format - no type prefix needed
        return await self.generate()

    def parse(self, roid: str) -> dict:
        """
        Parse a ROID into its components.

        Args:
            roid: ROID string to parse

        Returns:
            Dict with 'sequence' and 'suffix' keys
        """
        parts = roid.rsplit("-", 1)
        if len(parts) == 2:
            return {
                "sequence": int(parts[0]) if parts[0].isdigit() else parts[0],
                "suffix": parts[1]
            }
        return {
            "sequence": roid,
            "suffix": ""
        }

    def is_valid(self, roid: str) -> bool:
        """
        Validate ROID format.

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

        # Check sequence part is numeric
        if not parts[0].isdigit():
            return False

        # Check suffix is alphanumeric
        if not parts[1].isalnum():
            return False

        return True


# Global generator instance
_roid_generator: Optional[ROIDGenerator] = None


async def get_roid_generator(suffix: str = "AE") -> ROIDGenerator:
    """
    Get or create global ROID generator.

    Args:
        suffix: ROID suffix

    Returns:
        ROIDGenerator instance
    """
    global _roid_generator
    if _roid_generator is None:
        pool = await get_pool()
        _roid_generator = ROIDGenerator(pool, suffix)
    return _roid_generator


async def generate_roid(suffix: str = "AE") -> str:
    """
    Convenience function to generate a ROID.

    Args:
        suffix: ROID suffix

    Returns:
        New ROID string
    """
    generator = await get_roid_generator(suffix)
    return await generator.generate()
