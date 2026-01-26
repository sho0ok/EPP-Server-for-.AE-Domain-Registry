"""
Extension Repository

Handles database operations for zone extensions (restricted zones like .co.ae, .gov.ae).
"""

import logging
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional

from src.database.connection import get_pool, DatabasePool

logger = logging.getLogger("epp.extension_repo")


class ExtensionRepository:
    """Repository for zone extension operations."""

    def __init__(self, pool: DatabasePool):
        self.pool = pool

    # =========================================================================
    # Zone Extension Queries
    # =========================================================================

    async def get_zone_extensions(self, zone_id: int) -> List[Dict[str, Any]]:
        """
        Get all extensions enabled for a zone.

        Args:
            zone_id: Zone ID

        Returns:
            List of extension configurations
        """
        sql = """
            SELECT ze.ZON_EXT_ID, ze.ZON_ID, ze.EXT_ID,
                   e.CODE AS EXT_CODE, e.EXT_DESCRIPTION
            FROM ZONE_EXTENSIONS ze
            JOIN EXTENSIONS e ON ze.EXT_ID = e.EXT_ID
            WHERE ze.ZON_ID = :zone_id
        """
        return await self.pool.query(sql, {"zone_id": zone_id})

    async def get_zone_extension_by_name(
        self, zone_id: int, ext_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get a specific extension for a zone by name.

        Args:
            zone_id: Zone ID
            ext_name: Extension name (e.g., "aeEligibility")

        Returns:
            Extension configuration or None
        """
        sql = """
            SELECT ze.ZON_EXT_ID, ze.ZON_ID, ze.EXT_ID,
                   e.CODE AS EXT_CODE, e.EXT_DESCRIPTION
            FROM ZONE_EXTENSIONS ze
            JOIN EXTENSIONS e ON ze.EXT_ID = e.EXT_ID
            WHERE ze.ZON_ID = :zone_id AND e.CODE = :ext_code
        """
        return await self.pool.query_one(sql, {"zone_id": zone_id, "ext_code": ext_name})

    async def get_required_extension_fields(
        self, zone_id: int
    ) -> List[Dict[str, Any]]:
        """
        Get all required extension fields for a zone.

        Args:
            zone_id: Zone ID

        Returns:
            List of required fields with their configurations
        """
        sql = """
            SELECT zei.ZON_EXT_ITEM_ID, zei.ZON_ID, zei.EXT_ITEM_ID, zei.MANDATORY,
                   ei.ITEM_LABEL, ei.EXT_ID,
                   eif.EXT_ITEM_FIELD_ID, eif.FIELD_KEY, eif.FIELD_LABEL,
                   eif.FIELD_ITEM_TYPE_ID,
                   eif.FIELD_MIN_LENGTH, eif.FIELD_MAX_LENGTH,
                   e.CODE AS EXT_CODE, e.EXT_DESCRIPTION,
                   ze.ZON_EXT_ID
            FROM ZONE_EXT_ITEMS zei
            JOIN EXT_ITEMS ei ON zei.EXT_ITEM_ID = ei.EXT_ITEM_ID
            JOIN EXT_ITEM_FIELDS eif ON ei.EXT_ITEM_ID = eif.EXT_ITEM_ID
            JOIN EXTENSIONS e ON ei.EXT_ID = e.EXT_ID
            JOIN ZONE_EXTENSIONS ze ON ze.ZON_ID = zei.ZON_ID AND ze.EXT_ID = e.EXT_ID
            WHERE zei.ZON_ID = :zone_id
            ORDER BY e.CODE, ei.ITEM_LABEL, eif.FIELD_KEY
        """
        return await self.pool.query(sql, {"zone_id": zone_id})

    async def get_field_allowed_values(
        self, ext_item_field_id: int
    ) -> List[Dict[str, Any]]:
        """
        Get allowed values for an enum field.

        Args:
            ext_item_field_id: Extension item field ID

        Returns:
            List of allowed values
        """
        sql = """
            SELECT EXT_FIELD_VALUE_ID, VALUE_CODE, VALUE_LABEL, VALUE_ACTIVE
            FROM EXT_FIELD_VALUES
            WHERE EXT_ITEM_FIELD_ID = :field_id AND VALUE_ACTIVE = 'Y'
            ORDER BY VALUE_LABEL
        """
        return await self.pool.query(sql, {"field_id": ext_item_field_id})

    async def validate_field_value(
        self, ext_item_field_id: int, value: str
    ) -> bool:
        """
        Validate if a value is allowed for an enum field.

        Args:
            ext_item_field_id: Extension item field ID
            value: Value to validate

        Returns:
            True if valid, False otherwise
        """
        sql = """
            SELECT COUNT(*) AS cnt
            FROM EXT_FIELD_VALUES
            WHERE EXT_ITEM_FIELD_ID = :field_id
              AND VALUE_CODE = :value
              AND VALUE_ACTIVE = 'Y'
        """
        result = await self.pool.query_one(sql, {"field_id": ext_item_field_id, "value": value})
        return result and result.get("cnt", 0) > 0

    # =========================================================================
    # Domain Extension Data Operations
    # =========================================================================

    async def get_domain_extension_data(
        self, domain_roid: str
    ) -> List[Dict[str, Any]]:
        """
        Get all extension data for a domain.

        Args:
            domain_roid: Domain ROID

        Returns:
            List of extension field values
        """
        sql = """
            SELECT def.DOMAIN_FIELD_ID, def.DOM_ROID, def.ZON_EXT_ID,
                   def.EXT_ITEM_FIELD_ID, def.VALUE, def.UPDATE_DATE,
                   eif.FIELD_KEY, eif.FIELD_LABEL, eif.FIELD_ITEM_TYPE_ID,
                   ei.ITEM_LABEL,
                   e.CODE AS EXT_CODE, e.EXT_DESCRIPTION
            FROM DOMAIN_EXT_FIELD_DATA def
            JOIN EXT_ITEM_FIELDS eif ON def.EXT_ITEM_FIELD_ID = eif.EXT_ITEM_FIELD_ID
            JOIN EXT_ITEMS ei ON eif.EXT_ITEM_ID = ei.EXT_ITEM_ID
            JOIN EXTENSIONS e ON ei.EXT_ID = e.EXT_ID
            WHERE def.DOM_ROID = :domain_roid
            ORDER BY e.CODE, eif.FIELD_KEY
        """
        return await self.pool.query(sql, {"domain_roid": domain_roid})

    async def save_domain_extension_data(
        self,
        domain_roid: str,
        zon_ext_id: int,
        ext_item_field_id: int,
        value: str
    ) -> int:
        """
        Save extension field data for a domain.

        Args:
            domain_roid: Domain ROID
            zon_ext_id: Zone extension ID
            ext_item_field_id: Extension item field ID
            value: Field value

        Returns:
            New record ID
        """
        insert_sql = """
            INSERT INTO DOMAIN_EXT_FIELD_DATA (
                DOMAIN_FIELD_ID, DOM_ROID, ZON_EXT_ID, EXT_ITEM_FIELD_ID,
                VALUE, UPDATE_DATE
            ) VALUES (
                DOMAIN_FIELD_ID_SEQ.NEXTVAL, :domain_roid, :zon_ext_id, :ext_item_field_id,
                :value, SYSDATE
            )
        """
        await self.pool.execute(insert_sql, {
            "domain_roid": domain_roid,
            "zon_ext_id": zon_ext_id,
            "ext_item_field_id": ext_item_field_id,
            "value": value
        })

        # Get the ID
        id_sql = "SELECT DOMAIN_FIELD_ID_SEQ.CURRVAL AS domain_field_id FROM DUAL"
        result = await self.pool.query_one(id_sql, {})
        return result.get("domain_field_id", 0) if result else 0

    async def update_domain_extension_data(
        self,
        domain_roid: str,
        ext_item_field_id: int,
        value: str
    ) -> bool:
        """
        Update extension field data for a domain.

        Args:
            domain_roid: Domain ROID
            ext_item_field_id: Extension item field ID
            value: New field value

        Returns:
            True if updated, False if not found
        """
        sql = """
            UPDATE DOMAIN_EXT_FIELD_DATA
            SET VALUE = :value,
                UPDATE_DATE = SYSDATE
            WHERE DOM_ROID = :domain_roid
              AND EXT_ITEM_FIELD_ID = :ext_item_field_id
        """
        result = await self.pool.execute(sql, {
            "domain_roid": domain_roid,
            "ext_item_field_id": ext_item_field_id,
            "value": value
        })
        return result > 0

    async def delete_domain_extension_data(self, domain_roid: str) -> int:
        """
        Delete all extension data for a domain.

        Args:
            domain_roid: Domain ROID

        Returns:
            Number of records deleted
        """
        sql = "DELETE FROM DOMAIN_EXT_FIELD_DATA WHERE DOM_ROID = :domain_roid"
        return await self.pool.execute(sql, {"domain_roid": domain_roid})

    # =========================================================================
    # Validation Helpers
    # =========================================================================

    async def validate_extension_data(
        self,
        zone_id: int,
        extension_data: Dict[str, Dict[str, str]]
    ) -> List[str]:
        """
        Validate extension data for a zone.

        Args:
            zone_id: Zone ID
            extension_data: Dict of {ext_name: {field_key: value}}

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Get required fields for the zone
        required_fields = await self.get_required_extension_fields(zone_id)

        if not required_fields:
            # No extensions required for this zone
            return errors

        # Group by extension code
        fields_by_ext: Dict[str, List[Dict]] = {}
        for field in required_fields:
            ext_code = field["EXT_CODE"]
            if ext_code not in fields_by_ext:
                fields_by_ext[ext_code] = []
            fields_by_ext[ext_code].append(field)

        # Check each required extension
        for ext_name, fields in fields_by_ext.items():
            ext_data = extension_data.get(ext_name, {})

            for field in fields:
                field_key = field["FIELD_KEY"]
                # MANDATORY is 'true'/'false' or 'Y'/'N' in ZONE_EXT_ITEMS
                field_mandatory = field.get("MANDATORY") in ("true", "Y", True)

                value = ext_data.get(field_key)

                # Check required fields
                if field_mandatory and not value:
                    errors.append(
                        f"Missing required field '{field_key}' for extension '{ext_name}'"
                    )
                    continue

                if value:
                    # Validate field length
                    min_len = field.get("FIELD_MIN_LENGTH")
                    max_len = field.get("FIELD_MAX_LENGTH")

                    if min_len and len(value) < min_len:
                        errors.append(
                            f"Field '{field_key}' must be at least {min_len} characters"
                        )

                    if max_len and len(value) > max_len:
                        errors.append(
                            f"Field '{field_key}' must not exceed {max_len} characters"
                        )

                    # Validate enum values if field type is select/enum (type_id might vary)
                    field_id = field["EXT_ITEM_FIELD_ID"]
                    allowed = await self.get_field_allowed_values(field_id)
                    if allowed and not await self.validate_field_value(field_id, value):
                        allowed_codes = [v["VALUE_CODE"] for v in allowed]
                        errors.append(
                                f"Invalid value '{value}' for field '{field_key}'. "
                                f"Allowed values: {', '.join(allowed_codes)}"
                            )

        return errors

    async def get_extension_field_info(
        self, zone_id: int
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get extension field information for a zone (for building responses).

        Args:
            zone_id: Zone ID

        Returns:
            Dict of {ext_name: {field_key: field_info}}
        """
        fields = await self.get_required_extension_fields(zone_id)

        result: Dict[str, Dict[str, Any]] = {}
        for field in fields:
            ext_code = field["EXT_CODE"]
            if ext_code not in result:
                result[ext_code] = {
                    "description": field["EXT_DESCRIPTION"],
                    "zon_ext_id": field["ZON_EXT_ID"],
                    "fields": {}
                }

            field_key = field["FIELD_KEY"]
            result[ext_code]["fields"][field_key] = {
                "field_id": field["EXT_ITEM_FIELD_ID"],
                "label": field["FIELD_LABEL"],
                "type_id": field.get("FIELD_ITEM_TYPE_ID"),
                "mandatory": field.get("MANDATORY") in ("true", "Y", True),
                "min_length": field.get("FIELD_MIN_LENGTH"),
                "max_length": field.get("FIELD_MAX_LENGTH")
            }

        return result


# Global repository instance
_extension_repo: Optional[ExtensionRepository] = None


async def get_extension_repo() -> ExtensionRepository:
    """Get or create global extension repository."""
    global _extension_repo
    if _extension_repo is None:
        pool = await get_pool()
        _extension_repo = ExtensionRepository(pool)
    return _extension_repo
