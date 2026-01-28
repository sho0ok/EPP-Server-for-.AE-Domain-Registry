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

    # =========================================================================
    # AE Extension Registrant Operations
    # =========================================================================

    async def get_ae_registrant_data(
        self,
        domain_roid: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get AE extension registrant data for a domain.

        Args:
            domain_roid: Domain ROID

        Returns:
            Dict with AE properties or None if not found
        """
        sql = """
            SELECT
                ar.REGISTRANT_NAME,
                ar.REGISTRANT_ID,
                ar.REGISTRANT_ID_TYPE,
                ar.ELIGIBILITY_TYPE,
                ar.ELIGIBILITY_NAME,
                ar.ELIGIBILITY_ID,
                ar.ELIGIBILITY_ID_TYPE,
                ar.POLICY_REASON,
                ar.EXPLANATION,
                ar.CREATE_DATE,
                ar.UPDATE_DATE
            FROM AE_REGISTRANT_DATA ar
            WHERE ar.DOM_ROID = :domain_roid
        """
        return await self.pool.query_one(sql, {"domain_roid": domain_roid})

    async def update_ae_registrant_data(
        self,
        domain_roid: str,
        user_id: int,
        registrant_name: str,
        explanation: str,
        eligibility_type: Optional[str] = None,
        policy_reason: Optional[int] = None,
        registrant_id: Optional[str] = None,
        registrant_id_type: Optional[str] = None,
        eligibility_name: Optional[str] = None,
        eligibility_id: Optional[str] = None,
        eligibility_id_type: Optional[str] = None
    ) -> bool:
        """
        Update AE extension registrant data for a domain (ModifyRegistrant).

        This corrects eligibility data without changing the legal registrant.

        Args:
            domain_roid: Domain ROID
            user_id: User performing the update
            registrant_name: Legal name of registrant
            explanation: Explanation for the change (required, max 1000 chars)
            eligibility_type: Type of eligibility
            policy_reason: Policy reason (1-99)
            registrant_id: Registrant ID value
            registrant_id_type: Registrant ID type
            eligibility_name: Eligibility name
            eligibility_id: Eligibility ID value
            eligibility_id_type: Eligibility ID type

        Returns:
            True if updated successfully
        """
        # Check if record exists
        existing = await self.get_ae_registrant_data(domain_roid)

        if existing:
            # Update existing record
            sql = """
                UPDATE AE_REGISTRANT_DATA
                SET REGISTRANT_NAME = :registrant_name,
                    ELIGIBILITY_TYPE = COALESCE(:eligibility_type, ELIGIBILITY_TYPE),
                    POLICY_REASON = COALESCE(:policy_reason, POLICY_REASON),
                    REGISTRANT_ID = COALESCE(:registrant_id, REGISTRANT_ID),
                    REGISTRANT_ID_TYPE = COALESCE(:registrant_id_type, REGISTRANT_ID_TYPE),
                    ELIGIBILITY_NAME = COALESCE(:eligibility_name, ELIGIBILITY_NAME),
                    ELIGIBILITY_ID = COALESCE(:eligibility_id, ELIGIBILITY_ID),
                    ELIGIBILITY_ID_TYPE = COALESCE(:eligibility_id_type, ELIGIBILITY_ID_TYPE),
                    EXPLANATION = :explanation,
                    UPDATE_DATE = SYSDATE,
                    UPDATE_USER_ID = :user_id
                WHERE DOM_ROID = :domain_roid
            """
        else:
            # Insert new record
            sql = """
                INSERT INTO AE_REGISTRANT_DATA (
                    AE_REG_DATA_ID, DOM_ROID, REGISTRANT_NAME, REGISTRANT_ID,
                    REGISTRANT_ID_TYPE, ELIGIBILITY_TYPE, ELIGIBILITY_NAME,
                    ELIGIBILITY_ID, ELIGIBILITY_ID_TYPE, POLICY_REASON,
                    EXPLANATION, CREATE_DATE, CREATE_USER_ID, UPDATE_DATE, UPDATE_USER_ID
                ) VALUES (
                    AE_REG_DATA_SEQ.NEXTVAL, :domain_roid, :registrant_name, :registrant_id,
                    :registrant_id_type, :eligibility_type, :eligibility_name,
                    :eligibility_id, :eligibility_id_type, :policy_reason,
                    :explanation, SYSDATE, :user_id, SYSDATE, :user_id
                )
            """

        result = await self.pool.execute(sql, {
            "domain_roid": domain_roid,
            "user_id": user_id,
            "registrant_name": registrant_name,
            "explanation": explanation,
            "eligibility_type": eligibility_type,
            "policy_reason": policy_reason,
            "registrant_id": registrant_id,
            "registrant_id_type": registrant_id_type,
            "eligibility_name": eligibility_name,
            "eligibility_id": eligibility_id,
            "eligibility_id_type": eligibility_id_type
        })

        # Log the modification
        await self._log_ae_registrant_change(
            domain_roid=domain_roid,
            user_id=user_id,
            change_type="MODIFY",
            explanation=explanation
        )

        return result > 0

    async def transfer_ae_registrant(
        self,
        domain_roid: str,
        domain_name: str,
        account_id: int,
        user_id: int,
        registrant_name: str,
        explanation: str,
        eligibility_type: str,
        policy_reason: int,
        period: int = 1,
        period_unit: str = "y",
        registrant_id: Optional[str] = None,
        registrant_id_type: Optional[str] = None,
        eligibility_name: Optional[str] = None,
        eligibility_id: Optional[str] = None,
        eligibility_id_type: Optional[str] = None,
        rate: Decimal = Decimal("0")
    ) -> Dict[str, Any]:
        """
        Transfer domain to new legal registrant (RegistrantTransfer).

        This changes legal ownership and:
        - Sets new validity period starting from transfer completion
        - Charges create fee to the requesting client

        Args:
            domain_roid: Domain ROID
            domain_name: Domain name
            account_id: Account ID performing the transfer
            user_id: User performing the transfer
            registrant_name: New legal registrant name
            explanation: Explanation for the transfer
            eligibility_type: Type of eligibility (required)
            policy_reason: Policy reason (1-99, required)
            period: Validity period (default 1)
            period_unit: Period unit - 'y' for years, 'm' for months (default 'y')
            registrant_id: Registrant ID value
            registrant_id_type: Registrant ID type
            eligibility_name: Eligibility name
            eligibility_id: Eligibility ID value
            eligibility_id_type: Eligibility ID type
            rate: Fee to charge

        Returns:
            Dict with exDate (new expiration date)
        """
        # Calculate new expiry date
        if period_unit == "y":
            years = period
            months = 0
        else:
            years = period // 12
            months = period % 12

        # Update AE registrant data with new owner
        await self.update_ae_registrant_data(
            domain_roid=domain_roid,
            user_id=user_id,
            registrant_name=registrant_name,
            explanation=explanation,
            eligibility_type=eligibility_type,
            policy_reason=policy_reason,
            registrant_id=registrant_id,
            registrant_id_type=registrant_id_type,
            eligibility_name=eligibility_name,
            eligibility_id=eligibility_id,
            eligibility_id_type=eligibility_id_type
        )

        # Update domain with new expiry date (starting from now)
        update_domain_sql = """
            UPDATE DOMAINS
            SET EXPIRY_DATE = ADD_MONTHS(SYSDATE, :total_months),
                UPDATE_DATE = SYSDATE,
                UPDATE_USER_ID = :user_id
            WHERE ROID = :domain_roid
            RETURNING TO_CHAR(EXPIRY_DATE, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"') INTO :new_ex_date
        """
        total_months = years * 12 + months

        # Execute update and get new expiry date
        new_ex_date_sql = """
            SELECT TO_CHAR(
                ADD_MONTHS(SYSDATE, :total_months),
                'YYYY-MM-DD"T"HH24:MI:SS".0Z"'
            ) AS ex_date
            FROM DUAL
        """
        date_result = await self.pool.query_one(new_ex_date_sql, {"total_months": total_months})
        new_ex_date = date_result["ex_date"] if date_result else datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.0Z")

        # Update domain
        await self.pool.execute(
            """
            UPDATE DOMAINS
            SET EXPIRY_DATE = ADD_MONTHS(SYSDATE, :total_months),
                UPDATE_DATE = SYSDATE,
                UPDATE_USER_ID = :user_id
            WHERE ROID = :domain_roid
            """,
            {"total_months": total_months, "user_id": user_id, "domain_roid": domain_roid}
        )

        # Charge create fee
        if rate > 0:
            await self._charge_registrant_transfer_fee(
                account_id=account_id,
                domain_name=domain_name,
                amount=rate
            )

        # Log the transfer
        await self._log_ae_registrant_change(
            domain_roid=domain_roid,
            user_id=user_id,
            change_type="TRANSFER",
            explanation=explanation
        )

        return {"exDate": new_ex_date}

    async def _log_ae_registrant_change(
        self,
        domain_roid: str,
        user_id: int,
        change_type: str,
        explanation: str
    ) -> None:
        """Log AE registrant change for audit trail."""
        sql = """
            INSERT INTO AE_REGISTRANT_HISTORY (
                AE_REG_HIST_ID, DOM_ROID, CHANGE_TYPE, EXPLANATION,
                CHANGE_DATE, CHANGE_USER_ID
            ) VALUES (
                AE_REG_HIST_SEQ.NEXTVAL, :domain_roid, :change_type, :explanation,
                SYSDATE, :user_id
            )
        """
        try:
            await self.pool.execute(sql, {
                "domain_roid": domain_roid,
                "change_type": change_type,
                "explanation": explanation,
                "user_id": user_id
            })
        except Exception as e:
            # Log but don't fail the main operation
            logger.warning(f"Failed to log AE registrant change: {e}")

    async def _charge_registrant_transfer_fee(
        self,
        account_id: int,
        domain_name: str,
        amount: Decimal
    ) -> None:
        """Charge fee for registrant transfer."""
        sql = """
            INSERT INTO ACCOUNT_TRANSACTIONS (
                TRANSACTION_ID, ACCOUNT_ID, TRANSACTION_TYPE, AMOUNT,
                DESCRIPTION, TRANSACTION_DATE
            ) VALUES (
                ACCOUNT_TXN_SEQ.NEXTVAL, :account_id, 'REGISTRANT_TRANSFER', :amount,
                :description, SYSDATE
            )
        """
        await self.pool.execute(sql, {
            "account_id": account_id,
            "amount": -amount,  # Negative for charge
            "description": f"Registrant transfer fee for {domain_name}"
        })

        # Update account balance
        await self.pool.execute(
            "UPDATE ACCOUNTS SET BALANCE = BALANCE - :amount WHERE ACCOUNT_ID = :account_id",
            {"amount": amount, "account_id": account_id}
        )

    # =========================================================================
    # AU Extension Registrant Operations
    # =========================================================================

    async def get_au_registrant_data(
        self,
        domain_roid: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get AU extension registrant data for a domain.

        Args:
            domain_roid: Domain ROID

        Returns:
            Dict with AU properties or None if not found
        """
        sql = """
            SELECT
                ar.REGISTRANT_NAME,
                ar.REGISTRANT_ID,
                ar.REGISTRANT_ID_TYPE,
                ar.ELIGIBILITY_TYPE,
                ar.ELIGIBILITY_NAME,
                ar.ELIGIBILITY_ID,
                ar.ELIGIBILITY_ID_TYPE,
                ar.POLICY_REASON,
                ar.EXPLANATION,
                ar.CREATE_DATE,
                ar.UPDATE_DATE
            FROM AU_REGISTRANT_DATA ar
            WHERE ar.DOM_ROID = :domain_roid
        """
        return await self.pool.query_one(sql, {"domain_roid": domain_roid})

    async def update_au_registrant_data(
        self,
        domain_roid: str,
        user_id: int,
        registrant_name: str,
        explanation: str,
        eligibility_type: str,
        policy_reason: int,
        registrant_id: Optional[str] = None,
        registrant_id_type: Optional[str] = None,
        eligibility_name: Optional[str] = None,
        eligibility_id: Optional[str] = None,
        eligibility_id_type: Optional[str] = None
    ) -> bool:
        """
        Update AU extension registrant data for a domain (ModifyRegistrant).

        This corrects eligibility data without changing the legal registrant.

        Args:
            domain_roid: Domain ROID
            user_id: User performing the update
            registrant_name: Legal name of registrant
            explanation: Explanation for the change (required, max 1000 chars)
            eligibility_type: Type of eligibility (required)
            policy_reason: Policy reason (1-106, required)
            registrant_id: Registrant ID value
            registrant_id_type: Registrant ID type (ACN, ABN, OTHER)
            eligibility_name: Eligibility name
            eligibility_id: Eligibility ID value
            eligibility_id_type: Eligibility ID type

        Returns:
            True if updated successfully
        """
        # Check if record exists
        existing = await self.get_au_registrant_data(domain_roid)

        if existing:
            # Update existing record
            sql = """
                UPDATE AU_REGISTRANT_DATA
                SET REGISTRANT_NAME = :registrant_name,
                    ELIGIBILITY_TYPE = :eligibility_type,
                    POLICY_REASON = :policy_reason,
                    REGISTRANT_ID = COALESCE(:registrant_id, REGISTRANT_ID),
                    REGISTRANT_ID_TYPE = COALESCE(:registrant_id_type, REGISTRANT_ID_TYPE),
                    ELIGIBILITY_NAME = COALESCE(:eligibility_name, ELIGIBILITY_NAME),
                    ELIGIBILITY_ID = COALESCE(:eligibility_id, ELIGIBILITY_ID),
                    ELIGIBILITY_ID_TYPE = COALESCE(:eligibility_id_type, ELIGIBILITY_ID_TYPE),
                    EXPLANATION = :explanation,
                    UPDATE_DATE = SYSDATE,
                    UPDATE_USER_ID = :user_id
                WHERE DOM_ROID = :domain_roid
            """
        else:
            # Insert new record
            sql = """
                INSERT INTO AU_REGISTRANT_DATA (
                    AU_REG_DATA_ID, DOM_ROID, REGISTRANT_NAME, REGISTRANT_ID,
                    REGISTRANT_ID_TYPE, ELIGIBILITY_TYPE, ELIGIBILITY_NAME,
                    ELIGIBILITY_ID, ELIGIBILITY_ID_TYPE, POLICY_REASON,
                    EXPLANATION, CREATE_DATE, CREATE_USER_ID, UPDATE_DATE, UPDATE_USER_ID
                ) VALUES (
                    AU_REG_DATA_SEQ.NEXTVAL, :domain_roid, :registrant_name, :registrant_id,
                    :registrant_id_type, :eligibility_type, :eligibility_name,
                    :eligibility_id, :eligibility_id_type, :policy_reason,
                    :explanation, SYSDATE, :user_id, SYSDATE, :user_id
                )
            """

        result = await self.pool.execute(sql, {
            "domain_roid": domain_roid,
            "user_id": user_id,
            "registrant_name": registrant_name,
            "explanation": explanation,
            "eligibility_type": eligibility_type,
            "policy_reason": policy_reason,
            "registrant_id": registrant_id,
            "registrant_id_type": registrant_id_type,
            "eligibility_name": eligibility_name,
            "eligibility_id": eligibility_id,
            "eligibility_id_type": eligibility_id_type
        })

        # Log the modification
        await self._log_au_registrant_change(
            domain_roid=domain_roid,
            user_id=user_id,
            change_type="MODIFY",
            explanation=explanation
        )

        return result > 0

    async def transfer_au_registrant(
        self,
        domain_roid: str,
        domain_name: str,
        account_id: int,
        user_id: int,
        registrant_name: str,
        explanation: str,
        eligibility_type: str,
        policy_reason: int,
        period: int = 1,
        period_unit: str = "y",
        registrant_id: Optional[str] = None,
        registrant_id_type: Optional[str] = None,
        eligibility_name: Optional[str] = None,
        eligibility_id: Optional[str] = None,
        eligibility_id_type: Optional[str] = None,
        rate: Decimal = Decimal("0")
    ) -> Dict[str, Any]:
        """
        Transfer domain to new legal registrant (RegistrantTransfer) for .au.

        This changes legal ownership and:
        - Sets new validity period starting from transfer completion
        - Charges create fee to the requesting client

        Args:
            domain_roid: Domain ROID
            domain_name: Domain name
            account_id: Account ID performing the transfer
            user_id: User performing the transfer
            registrant_name: New legal registrant name
            explanation: Explanation for the transfer
            eligibility_type: Type of eligibility (required)
            policy_reason: Policy reason (1-106, required)
            period: Validity period (default 1)
            period_unit: Period unit - 'y' for years, 'm' for months (default 'y')
            registrant_id: Registrant ID value
            registrant_id_type: Registrant ID type
            eligibility_name: Eligibility name
            eligibility_id: Eligibility ID value
            eligibility_id_type: Eligibility ID type
            rate: Fee to charge

        Returns:
            Dict with exDate (new expiration date)
        """
        # Calculate new expiry date
        if period_unit == "y":
            years = period
            months = 0
        else:
            years = period // 12
            months = period % 12

        # Update AU registrant data with new owner
        await self.update_au_registrant_data(
            domain_roid=domain_roid,
            user_id=user_id,
            registrant_name=registrant_name,
            explanation=explanation,
            eligibility_type=eligibility_type,
            policy_reason=policy_reason,
            registrant_id=registrant_id,
            registrant_id_type=registrant_id_type,
            eligibility_name=eligibility_name,
            eligibility_id=eligibility_id,
            eligibility_id_type=eligibility_id_type
        )

        # Calculate total months for new expiry
        total_months = years * 12 + months

        # Get new expiry date
        new_ex_date_sql = """
            SELECT TO_CHAR(
                ADD_MONTHS(SYSDATE, :total_months),
                'YYYY-MM-DD"T"HH24:MI:SS".0Z"'
            ) AS ex_date
            FROM DUAL
        """
        date_result = await self.pool.query_one(new_ex_date_sql, {"total_months": total_months})
        new_ex_date = date_result["ex_date"] if date_result else datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.0Z")

        # Update domain with new expiry date
        await self.pool.execute(
            """
            UPDATE DOMAINS
            SET EXPIRY_DATE = ADD_MONTHS(SYSDATE, :total_months),
                UPDATE_DATE = SYSDATE,
                UPDATE_USER_ID = :user_id
            WHERE ROID = :domain_roid
            """,
            {"total_months": total_months, "user_id": user_id, "domain_roid": domain_roid}
        )

        # Charge create fee
        if rate > 0:
            await self._charge_registrant_transfer_fee(
                account_id=account_id,
                domain_name=domain_name,
                amount=rate
            )

        # Log the transfer
        await self._log_au_registrant_change(
            domain_roid=domain_roid,
            user_id=user_id,
            change_type="TRANSFER",
            explanation=explanation
        )

        return {"exDate": new_ex_date}

    async def _log_au_registrant_change(
        self,
        domain_roid: str,
        user_id: int,
        change_type: str,
        explanation: str
    ) -> None:
        """Log AU registrant change for audit trail."""
        sql = """
            INSERT INTO AU_REGISTRANT_HISTORY (
                AU_REG_HIST_ID, DOM_ROID, CHANGE_TYPE, EXPLANATION,
                CHANGE_DATE, CHANGE_USER_ID
            ) VALUES (
                AU_REG_HIST_SEQ.NEXTVAL, :domain_roid, :change_type, :explanation,
                SYSDATE, :user_id
            )
        """
        try:
            await self.pool.execute(sql, {
                "domain_roid": domain_roid,
                "change_type": change_type,
                "explanation": explanation,
                "user_id": user_id
            })
        except Exception as e:
            # Log but don't fail the main operation
            logger.warning(f"Failed to log AU registrant change: {e}")


    # =========================================================================
    # Phase 7: secDNS (DNSSEC) Operations
    # =========================================================================

    async def get_domain_secdns_data(
        self, domain_roid: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get DNSSEC data for a domain.

        Args:
            domain_roid: Domain ROID

        Returns:
            Dict with ds_data, key_data or None
        """
        # Get Key records first (they link to DS data)
        key_sql = """
            SELECT KEY_DATA_ID, DOM_ROID, FLAGS, PROTOCOL, ALGORITHM, PUBLIC_KEY
            FROM DNSSEC_KEY_DATA
            WHERE DOM_ROID = :domain_roid
            ORDER BY FLAGS DESC
        """
        key_records = await self.pool.query(key_sql, {"domain_roid": domain_roid})

        # Get DS records (linked via KEY_DATA_ID or VARIANT_ID)
        ds_sql = """
            SELECT d.SEC_ID, d.VARIANT_ID, d.KEY_DATA_ID,
                   d.DNSSEC_KEYTAG, d.DNSSEC_ALGORITHM, d.DNSSEC_DIGEST_TYPE, d.DNSSEC_DIGEST,
                   k.FLAGS, k.PROTOCOL, k.ALGORITHM AS KEY_ALG, k.PUBLIC_KEY
            FROM DNSSEC_DS_DATA d
            LEFT JOIN DNSSEC_KEY_DATA k ON d.KEY_DATA_ID = k.KEY_DATA_ID
            WHERE k.DOM_ROID = :domain_roid
            ORDER BY d.DNSSEC_KEYTAG
        """
        ds_records = await self.pool.query(ds_sql, {"domain_roid": domain_roid})

        if not ds_records and not key_records:
            return None

        result = {
            "ds_data": [],
            "key_data": [],
            "max_sig_life": None
        }

        for ds in ds_records:
            ds_entry = {
                "keyTag": ds["DNSSEC_KEYTAG"],
                "alg": ds["DNSSEC_ALGORITHM"],
                "digestType": ds["DNSSEC_DIGEST_TYPE"],
                "digest": ds["DNSSEC_DIGEST"]
            }
            # Check for embedded key data
            if ds.get("FLAGS"):
                ds_entry["keyData"] = {
                    "flags": ds["FLAGS"],
                    "protocol": ds["PROTOCOL"],
                    "alg": ds["KEY_ALG"],
                    "pubKey": ds["PUBLIC_KEY"]
                }
            result["ds_data"].append(ds_entry)

        for key in key_records:
            result["key_data"].append({
                "flags": key["FLAGS"],
                "protocol": key["PROTOCOL"],
                "alg": key["ALGORITHM"],
                "pubKey": key["PUBLIC_KEY"]
            })

        return result

    async def save_domain_secdns_data(
        self,
        domain_roid: str,
        ds_data: List[Dict[str, Any]] = None,
        key_data: List[Dict[str, Any]] = None,
        max_sig_life: int = None
    ) -> None:
        """
        Save DNSSEC data for a domain.

        Args:
            domain_roid: Domain ROID
            ds_data: List of DS records
            key_data: List of Key records
            max_sig_life: Maximum signature lifetime
        """
        # Save max sig life config
        if max_sig_life:
            await self.pool.execute("""
                MERGE INTO DOMAIN_DNSSEC_CONFIG c
                USING (SELECT :domain_roid AS dom_roid FROM DUAL) src
                ON (c.DOM_ROID = src.dom_roid)
                WHEN MATCHED THEN UPDATE SET MAX_SIG_LIFE = :max_sig_life
                WHEN NOT MATCHED THEN INSERT (CONFIG_ID, DOM_ROID, MAX_SIG_LIFE)
                    VALUES (DNSSEC_CONFIG_SEQ.NEXTVAL, :domain_roid, :max_sig_life)
            """, {"domain_roid": domain_roid, "max_sig_life": max_sig_life})

        # Save DS records
        if ds_data:
            for ds in ds_data:
                key_info = ds.get("keyData", {})
                await self.pool.execute("""
                    INSERT INTO DOMAIN_DNSSEC_DS (
                        DS_ID, DOM_ROID, KEY_TAG, ALG, DIGEST_TYPE, DIGEST,
                        KEY_FLAGS, KEY_PROTOCOL, KEY_ALG, PUB_KEY, CREATE_DATE
                    ) VALUES (
                        DNSSEC_DS_SEQ.NEXTVAL, :domain_roid, :key_tag, :alg,
                        :digest_type, :digest, :key_flags, :key_protocol,
                        :key_alg, :pub_key, SYSDATE
                    )
                """, {
                    "domain_roid": domain_roid,
                    "key_tag": ds.get("keyTag"),
                    "alg": ds.get("alg"),
                    "digest_type": ds.get("digestType"),
                    "digest": ds.get("digest"),
                    "key_flags": key_info.get("flags"),
                    "key_protocol": key_info.get("protocol"),
                    "key_alg": key_info.get("alg"),
                    "pub_key": key_info.get("pubKey")
                })

        # Save standalone Key records
        if key_data:
            for key in key_data:
                await self.pool.execute("""
                    INSERT INTO DOMAIN_DNSSEC_KEY (
                        KEY_ID, DOM_ROID, FLAGS, PROTOCOL, ALG, PUB_KEY, CREATE_DATE
                    ) VALUES (
                        DNSSEC_KEY_SEQ.NEXTVAL, :domain_roid, :flags, :protocol,
                        :alg, :pub_key, SYSDATE
                    )
                """, {
                    "domain_roid": domain_roid,
                    "flags": key.get("flags"),
                    "protocol": key.get("protocol"),
                    "alg": key.get("alg"),
                    "pub_key": key.get("pubKey")
                })

    async def delete_domain_secdns_data(
        self,
        domain_roid: str,
        ds_data: List[Dict[str, Any]] = None,
        key_data: List[Dict[str, Any]] = None,
        remove_all: bool = False
    ) -> None:
        """
        Delete DNSSEC data from a domain.

        Args:
            domain_roid: Domain ROID
            ds_data: Specific DS records to remove
            key_data: Specific Key records to remove
            remove_all: Remove all DNSSEC data
        """
        if remove_all:
            await self.pool.execute(
                "DELETE FROM DOMAIN_DNSSEC_DS WHERE DOM_ROID = :domain_roid",
                {"domain_roid": domain_roid}
            )
            await self.pool.execute(
                "DELETE FROM DOMAIN_DNSSEC_KEY WHERE DOM_ROID = :domain_roid",
                {"domain_roid": domain_roid}
            )
            await self.pool.execute(
                "DELETE FROM DOMAIN_DNSSEC_CONFIG WHERE DOM_ROID = :domain_roid",
                {"domain_roid": domain_roid}
            )
            return

        if ds_data:
            for ds in ds_data:
                await self.pool.execute("""
                    DELETE FROM DOMAIN_DNSSEC_DS
                    WHERE DOM_ROID = :domain_roid
                      AND KEY_TAG = :key_tag
                      AND ALG = :alg
                      AND DIGEST_TYPE = :digest_type
                """, {
                    "domain_roid": domain_roid,
                    "key_tag": ds.get("keyTag"),
                    "alg": ds.get("alg"),
                    "digest_type": ds.get("digestType")
                })

        if key_data:
            for key in key_data:
                await self.pool.execute("""
                    DELETE FROM DOMAIN_DNSSEC_KEY
                    WHERE DOM_ROID = :domain_roid
                      AND FLAGS = :flags
                      AND ALG = :alg
                """, {
                    "domain_roid": domain_roid,
                    "flags": key.get("flags"),
                    "alg": key.get("alg")
                })

    # =========================================================================
    # Phase 8: IDN Extension Operations
    # =========================================================================

    async def get_domain_idn_data(
        self, domain_roid: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get IDN data for a domain.

        Args:
            domain_roid: Domain ROID

        Returns:
            Dict with userForm, language, canonicalForm or None
        """
        sql = """
            SELECT USER_FORM, LANGUAGE, CANONICAL_FORM
            FROM DOMAIN_IDN
            WHERE DOM_ROID = :domain_roid
        """
        return await self.pool.query_one(sql, {"domain_roid": domain_roid})

    async def save_domain_idn_data(
        self,
        domain_roid: str,
        user_form: str,
        language: str,
        canonical_form: str = None
    ) -> None:
        """
        Save IDN data for a domain.

        Args:
            domain_roid: Domain ROID
            user_form: Unicode user form
            language: BCP 47 language tag
            canonical_form: Server-computed canonical form
        """
        await self.pool.execute("""
            MERGE INTO DOMAIN_IDN i
            USING (SELECT :domain_roid AS dom_roid FROM DUAL) src
            ON (i.DOM_ROID = src.dom_roid)
            WHEN MATCHED THEN UPDATE SET
                USER_FORM = :user_form,
                LANGUAGE = :language,
                CANONICAL_FORM = :canonical_form,
                UPDATE_DATE = SYSDATE
            WHEN NOT MATCHED THEN INSERT (
                IDN_ID, DOM_ROID, USER_FORM, LANGUAGE, CANONICAL_FORM, CREATE_DATE
            ) VALUES (
                DOMAIN_IDN_SEQ.NEXTVAL, :domain_roid, :user_form, :language,
                :canonical_form, SYSDATE
            )
        """, {
            "domain_roid": domain_roid,
            "user_form": user_form,
            "language": language,
            "canonical_form": canonical_form
        })

    # =========================================================================
    # Phase 9: Variant Extension Operations
    # =========================================================================

    async def get_domain_variants(
        self, domain_roid: str
    ) -> List[Dict[str, Any]]:
        """
        Get variants for a domain.

        Args:
            domain_roid: Domain ROID

        Returns:
            List of variants with name and userForm
        """
        sql = """
            SELECT VARIANT_ID, DMV_A_LABEL AS VARIANT_NAME, DMV_U_LABEL AS USER_FORM, DMV_ZONE
            FROM DOMAIN_VARIANTS
            WHERE DMV_DOM_ROID = :domain_roid
            ORDER BY DMV_A_LABEL
        """
        return await self.pool.query(sql, {"domain_roid": domain_roid})

    async def add_domain_variants(
        self,
        domain_roid: str,
        variants: List[Dict[str, str]]
    ) -> None:
        """
        Add variants to a domain.

        Args:
            domain_roid: Domain ROID
            variants: List of variants with name and userForm
        """
        for variant in variants:
            await self.pool.execute("""
                INSERT INTO DOMAIN_VARIANTS (
                    VARIANT_ID, DOM_ROID, VARIANT_NAME, USER_FORM, CREATE_DATE
                ) VALUES (
                    DOMAIN_VARIANT_SEQ.NEXTVAL, :domain_roid, :name, :user_form, SYSDATE
                )
            """, {
                "domain_roid": domain_roid,
                "name": variant.get("name"),
                "user_form": variant.get("userForm")
            })

    async def remove_domain_variants(
        self,
        domain_roid: str,
        variant_names: List[str]
    ) -> int:
        """
        Remove variants from a domain.

        Args:
            domain_roid: Domain ROID
            variant_names: List of variant DNS names to remove

        Returns:
            Number of variants removed
        """
        count = 0
        for name in variant_names:
            result = await self.pool.execute("""
                DELETE FROM DOMAIN_VARIANTS
                WHERE DOM_ROID = :domain_roid AND VARIANT_NAME = :name
            """, {"domain_roid": domain_roid, "name": name})
            count += result
        return count

    # =========================================================================
    # Phase 11: KV Extension Operations
    # =========================================================================

    async def get_domain_kv_data(
        self, domain_roid: str
    ) -> List[Dict[str, Any]]:
        """
        Get key-value data for a domain.

        Args:
            domain_roid: Domain ROID

        Returns:
            List of KV lists with their items
        """
        sql = """
            SELECT LIST_NAME, KEY_NAME, VALUE
            FROM DOMAIN_KV
            WHERE DOM_ROID = :domain_roid
            ORDER BY LIST_NAME, KEY_NAME
        """
        rows = await self.pool.query(sql, {"domain_roid": domain_roid})

        # Group by list name
        lists: Dict[str, List[Dict[str, str]]] = {}
        for row in rows:
            list_name = row["LIST_NAME"]
            if list_name not in lists:
                lists[list_name] = []
            lists[list_name].append({
                "key": row["KEY_NAME"],
                "value": row["VALUE"]
            })

        return [{"name": name, "items": items} for name, items in lists.items()]

    async def save_domain_kv_data(
        self,
        domain_roid: str,
        kvlists: List[Dict[str, Any]]
    ) -> None:
        """
        Save key-value data for a domain.

        Args:
            domain_roid: Domain ROID
            kvlists: List of KV lists with items
        """
        for kvlist in kvlists:
            list_name = kvlist.get("name", "")
            items = kvlist.get("items", [])

            # Delete existing items for this list
            await self.pool.execute("""
                DELETE FROM DOMAIN_KV
                WHERE DOM_ROID = :domain_roid AND LIST_NAME = :list_name
            """, {"domain_roid": domain_roid, "list_name": list_name})

            # Insert new items
            for item in items:
                await self.pool.execute("""
                    INSERT INTO DOMAIN_KV (
                        KV_ID, DOM_ROID, LIST_NAME, KEY_NAME, VALUE, CREATE_DATE
                    ) VALUES (
                        DOMAIN_KV_SEQ.NEXTVAL, :domain_roid, :list_name,
                        :key_name, :value, SYSDATE
                    )
                """, {
                    "domain_roid": domain_roid,
                    "list_name": list_name,
                    "key_name": item.get("key"),
                    "value": item.get("value")
                })

    async def delete_domain_kv_data(
        self, domain_roid: str, list_name: str = None
    ) -> int:
        """
        Delete key-value data for a domain.

        Args:
            domain_roid: Domain ROID
            list_name: Specific list to delete, or None for all

        Returns:
            Number of records deleted
        """
        if list_name:
            return await self.pool.execute("""
                DELETE FROM DOMAIN_KV
                WHERE DOM_ROID = :domain_roid AND LIST_NAME = :list_name
            """, {"domain_roid": domain_roid, "list_name": list_name})
        else:
            return await self.pool.execute(
                "DELETE FROM DOMAIN_KV WHERE DOM_ROID = :domain_roid",
                {"domain_roid": domain_roid}
            )


# Global repository instance
_extension_repo: Optional[ExtensionRepository] = None


async def get_extension_repo() -> ExtensionRepository:
    """Get or create global extension repository."""
    global _extension_repo
    if _extension_repo is None:
        pool = await get_pool()
        _extension_repo = ExtensionRepository(pool)
    return _extension_repo
