"""
Contact Repository

Handles all contact-related database operations including:
- Availability checks
- Contact info retrieval
- Contact creation, update, deletion
"""

import logging
from datetime import datetime, date
from typing import Any, Dict, List, Optional, Tuple

from src.database.connection import get_pool, DatabasePool
from src.database.models import ContactInfo

logger = logging.getLogger("epp.database.contact")


class ContactRepository:
    """
    Repository for contact operations.

    All queries use parameterized statements to prevent SQL injection.
    """

    def __init__(self, pool: DatabasePool):
        """Initialize with database pool."""
        self.pool = pool

    # ========================================================================
    # Check Operations
    # ========================================================================

    async def check_available(self, contact_id: str) -> Tuple[bool, Optional[str]]:
        """
        Check if contact ID is available.

        Args:
            contact_id: Contact identifier

        Returns:
            Tuple of (is_available, reason_if_not)
        """
        sql = """
            SELECT c.CON_ROID, o.OBJ_STATUS
            FROM CONTACTS c
            JOIN REGISTRY_OBJECTS o ON c.CON_ROID = o.OBJ_ROID
            WHERE c.CON_UID = :contact_id
        """

        row = await self.pool.query_one(sql, {"contact_id": contact_id})

        if row:
            return False, "In use"

        return True, None

    async def check_multiple(
        self,
        contact_ids: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Check availability of multiple contacts.

        Args:
            contact_ids: List of contact IDs to check

        Returns:
            List of {id, avail, reason} dicts
        """
        results = []
        for cid in contact_ids:
            avail, reason = await self.check_available(cid)
            results.append({
                "id": cid,
                "avail": avail,
                "reason": reason
            })
        return results

    # ========================================================================
    # Info Operations
    # ========================================================================

    async def get_by_uid(
        self,
        contact_id: str,
        include_auth: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Get contact by user ID.

        Args:
            contact_id: Contact identifier (CON_UID)
            include_auth: Whether to include auth info

        Returns:
            Contact data dict or None
        """
        sql = """
            SELECT
                c.CON_ROID,
                c.CON_UID,
                c.CON_NAME,
                c.CON_ORG,
                c.CON_STREET1,
                c.CON_STREET2,
                c.CON_STREET3,
                c.CON_CITY,
                c.CON_STATE,
                c.CON_POSTCODE,
                c.CON_COUNTRY,
                c.CON_PHONE,
                c.CON_PHONE_EXT,
                c.CON_FAX,
                c.CON_FAX_EXT,
                c.CON_EMAIL,
                o.OBJ_STATUS,
                o.OBJ_PASSWORD,
                o.OBJ_CREATE_DATE,
                o.OBJ_CREATE_USER_ID,
                o.OBJ_MANAGE_ACCOUNT_ID,
                o.OBJ_UPDATE_DATE,
                o.OBJ_UPDATE_USER_ID,
                cr_user.USR_USERNAME AS CR_USERNAME,
                up_user.USR_USERNAME AS UP_USERNAME,
                acc.ACC_CLIENT_ID AS CL_ID
            FROM CONTACTS c
            JOIN REGISTRY_OBJECTS o ON c.CON_ROID = o.OBJ_ROID
            LEFT JOIN USERS cr_user ON o.OBJ_CREATE_USER_ID = cr_user.USR_ID
            LEFT JOIN USERS up_user ON o.OBJ_UPDATE_USER_ID = up_user.USR_ID
            LEFT JOIN ACCOUNTS acc ON o.OBJ_MANAGE_ACCOUNT_ID = acc.ACC_ID
            WHERE c.CON_UID = :contact_id
        """

        row = await self.pool.query_one(sql, {"contact_id": contact_id})

        if not row:
            return None

        roid = row["CON_ROID"]

        # Get statuses
        statuses = await self._get_contact_statuses(roid)

        # Build postal info
        postal_info = self._build_postal_info(row)

        # Build response
        contact_data = {
            "id": row["CON_UID"],
            "roid": roid,
            "statuses": statuses,
            "postalInfo_int": postal_info,  # Using 'int' type for international
            "postalInfo_loc": None,  # Local type not commonly used
            "voice": row["CON_PHONE"],
            "voice_ext": row["CON_PHONE_EXT"],
            "fax": row["CON_FAX"],
            "fax_ext": row["CON_FAX_EXT"],
            "email": row["CON_EMAIL"],
            "clID": row["CL_ID"] or "",
            "crID": row["CR_USERNAME"],
            "crDate": self._format_date(row["OBJ_CREATE_DATE"]),
            "upID": row["UP_USERNAME"],
            "upDate": self._format_date(row["OBJ_UPDATE_DATE"]),
            "authInfo": row["OBJ_PASSWORD"] if include_auth else None,
            # Additional fields for internal use
            "_account_id": row["OBJ_MANAGE_ACCOUNT_ID"],
        }

        return contact_data

    async def get_by_roid(
        self,
        roid: str,
        include_auth: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Get contact by ROID.

        Args:
            roid: Registry Object ID
            include_auth: Whether to include auth info

        Returns:
            Contact data dict or None
        """
        sql = "SELECT CON_UID FROM CONTACTS WHERE CON_ROID = :roid"
        uid = await self.pool.query_value(sql, {"roid": roid})

        if not uid:
            return None

        return await self.get_by_uid(uid, include_auth)

    async def _get_contact_statuses(self, roid: str) -> List[Dict[str, Any]]:
        """Get EPP statuses for contact."""
        sql = """
            SELECT ECS_STATUS, ECS_LANG, ECS_REASON
            FROM EPP_CONTACT_STATUSES
            WHERE ECS_ROID = :roid
        """
        rows = await self.pool.query(sql, {"roid": roid})

        statuses = []
        for row in rows:
            statuses.append({
                "s": row["ECS_STATUS"],
                "lang": row.get("ECS_LANG"),
                "reason": row.get("ECS_REASON")
            })

        # Add default status if none
        if not statuses:
            statuses.append({"s": "ok"})

        return statuses

    def _build_postal_info(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Build postal info dict from database row."""
        streets = []
        if row.get("CON_STREET1"):
            streets.append(row["CON_STREET1"])
        if row.get("CON_STREET2"):
            streets.append(row["CON_STREET2"])
        if row.get("CON_STREET3"):
            streets.append(row["CON_STREET3"])

        return {
            "name": row.get("CON_NAME"),
            "org": row.get("CON_ORG"),
            "street": streets,
            "city": row.get("CON_CITY"),
            "sp": row.get("CON_STATE"),
            "pc": row.get("CON_POSTCODE"),
            "cc": row.get("CON_COUNTRY"),
        }

    # ========================================================================
    # Authorization Operations
    # ========================================================================

    async def verify_auth_info(
        self,
        contact_id: str,
        auth_info: str
    ) -> bool:
        """
        Verify contact auth info password.

        Args:
            contact_id: Contact ID
            auth_info: Auth info to verify

        Returns:
            True if auth info matches
        """
        sql = """
            SELECT o.OBJ_PASSWORD
            FROM CONTACTS c
            JOIN REGISTRY_OBJECTS o ON c.CON_ROID = o.OBJ_ROID
            WHERE c.CON_UID = :contact_id
        """
        stored = await self.pool.query_value(sql, {"contact_id": contact_id})

        if not stored:
            return False

        return stored == auth_info

    async def get_sponsoring_account(self, contact_id: str) -> Optional[int]:
        """
        Get account ID that sponsors the contact.

        Args:
            contact_id: Contact ID

        Returns:
            Account ID or None
        """
        sql = """
            SELECT o.OBJ_MANAGE_ACCOUNT_ID
            FROM CONTACTS c
            JOIN REGISTRY_OBJECTS o ON c.CON_ROID = o.OBJ_ROID
            WHERE c.CON_UID = :contact_id
        """
        result = await self.pool.query_value(sql, {"contact_id": contact_id})
        return int(result) if result else None

    # ========================================================================
    # Usage Check Operations
    # ========================================================================

    async def is_in_use(self, contact_id: str) -> Tuple[bool, Optional[str]]:
        """
        Check if contact is in use by any domains.

        Args:
            contact_id: Contact ID

        Returns:
            Tuple of (is_in_use, usage_description)
        """
        # Get ROID first
        sql = "SELECT CON_ROID FROM CONTACTS WHERE CON_UID = :contact_id"
        roid = await self.pool.query_value(sql, {"contact_id": contact_id})

        if not roid:
            return False, None

        # Check if used as registrant
        sql = """
            SELECT COUNT(*) FROM DOMAINS
            WHERE DOM_REGISTRANT_ROID = :roid
        """
        count = await self.pool.query_value(sql, {"roid": roid})
        if count and int(count) > 0:
            return True, f"Used as registrant for {count} domain(s)"

        # Check if used as contact
        sql = """
            SELECT COUNT(*) FROM DOMAIN_CONTACTS
            WHERE DCN_CONTACT_ROID = :roid
        """
        count = await self.pool.query_value(sql, {"roid": roid})
        if count and int(count) > 0:
            return True, f"Used as contact for {count} domain(s)"

        return False, None

    async def get_linked_domains(self, contact_id: str) -> List[str]:
        """
        Get list of domains linked to this contact.

        Args:
            contact_id: Contact ID

        Returns:
            List of domain names
        """
        sql = "SELECT CON_ROID FROM CONTACTS WHERE CON_UID = :contact_id"
        roid = await self.pool.query_value(sql, {"contact_id": contact_id})

        if not roid:
            return []

        domains = []

        # Domains where contact is registrant
        sql = """
            SELECT DOM_NAME FROM DOMAINS
            WHERE DOM_REGISTRANT_ROID = :roid
        """
        rows = await self.pool.query(sql, {"roid": roid})
        domains.extend([row["DOM_NAME"] for row in rows])

        # Domains where contact is admin/tech/billing
        sql = """
            SELECT d.DOM_NAME
            FROM DOMAIN_CONTACTS dc
            JOIN DOMAINS d ON dc.DCN_DOMAIN_ROID = d.DOM_ROID
            WHERE dc.DCN_CONTACT_ROID = :roid
        """
        rows = await self.pool.query(sql, {"roid": roid})
        domains.extend([row["DOM_NAME"] for row in rows])

        return list(set(domains))  # Remove duplicates

    # ========================================================================
    # ROID Lookup
    # ========================================================================

    async def get_roid(self, contact_id: str) -> Optional[str]:
        """
        Get ROID for contact ID.

        Args:
            contact_id: Contact ID

        Returns:
            ROID or None
        """
        sql = "SELECT CON_ROID FROM CONTACTS WHERE CON_UID = :contact_id"
        return await self.pool.query_value(sql, {"contact_id": contact_id})

    # ========================================================================
    # Create Operations
    # ========================================================================

    async def create(
        self,
        contact_id: str,
        email: str,
        auth_info: str,
        user_id: int,
        account_id: int,
        roid: str,
        name: Optional[str] = None,
        org: Optional[str] = None,
        street1: Optional[str] = None,
        street2: Optional[str] = None,
        street3: Optional[str] = None,
        city: Optional[str] = None,
        state: Optional[str] = None,
        postcode: Optional[str] = None,
        country: Optional[str] = None,
        phone: Optional[str] = None,
        phone_ext: Optional[str] = None,
        fax: Optional[str] = None,
        fax_ext: Optional[str] = None
    ) -> str:
        """
        Create a new contact.

        Args:
            contact_id: Contact identifier (CON_UID)
            email: Email address
            auth_info: Authorization info password
            user_id: Creating user ID
            account_id: Managing account ID
            roid: Pre-generated ROID
            name: Contact name
            org: Organization
            street1-3: Street address lines
            city: City
            state: State/province
            postcode: Postal code
            country: Country code (ISO 3166)
            phone: Phone number (E.164)
            phone_ext: Phone extension
            fax: Fax number (E.164)
            fax_ext: Fax extension

        Returns:
            ROID of created contact
        """
        now = datetime.utcnow()

        # Insert into REGISTRY_OBJECTS
        sql_obj = """
            INSERT INTO REGISTRY_OBJECTS (
                OBJ_ROID, OBJ_TYPE, OBJ_PASSWORD, OBJ_STATUS,
                OBJ_CREATE_DATE, OBJ_CREATE_USER_ID, OBJ_MANAGE_ACCOUNT_ID,
                OBJ_LOCKED
            ) VALUES (
                :roid, 'contact', :auth_info, 'ok',
                :create_date, :user_id, :account_id,
                'N'
            )
        """
        await self.pool.execute(sql_obj, {
            "roid": roid,
            "auth_info": auth_info,
            "create_date": now,
            "user_id": user_id,
            "account_id": account_id
        }, commit=False)

        # Insert into CONTACTS
        sql_con = """
            INSERT INTO CONTACTS (
                CON_ROID, CON_UID, CON_NAME, CON_ORG,
                CON_STREET1, CON_STREET2, CON_STREET3,
                CON_CITY, CON_STATE, CON_POSTCODE, CON_COUNTRY,
                CON_PHONE, CON_PHONE_EXT, CON_FAX, CON_FAX_EXT,
                CON_EMAIL
            ) VALUES (
                :roid, :contact_id, :name, :org,
                :street1, :street2, :street3,
                :city, :state, :postcode, :country,
                :phone, :phone_ext, :fax, :fax_ext,
                :email
            )
        """
        await self.pool.execute(sql_con, {
            "roid": roid,
            "contact_id": contact_id,
            "name": name,
            "org": org,
            "street1": street1,
            "street2": street2,
            "street3": street3,
            "city": city,
            "state": state,
            "postcode": postcode,
            "country": country,
            "phone": phone,
            "phone_ext": phone_ext,
            "fax": fax,
            "fax_ext": fax_ext,
            "email": email
        }, commit=False)

        # Add default status
        await self._add_status(roid, "ok", commit=False)

        # Commit transaction
        async with self.pool.acquire() as conn:
            await conn.commit()

        logger.info(f"Created contact {contact_id} with ROID {roid}")
        return roid

    # ========================================================================
    # Update Operations
    # ========================================================================

    async def update(
        self,
        contact_id: str,
        user_id: int,
        name: Optional[str] = None,
        org: Optional[str] = None,
        street1: Optional[str] = None,
        street2: Optional[str] = None,
        street3: Optional[str] = None,
        city: Optional[str] = None,
        state: Optional[str] = None,
        postcode: Optional[str] = None,
        country: Optional[str] = None,
        phone: Optional[str] = None,
        phone_ext: Optional[str] = None,
        fax: Optional[str] = None,
        fax_ext: Optional[str] = None,
        email: Optional[str] = None,
        auth_info: Optional[str] = None,
        add_statuses: Optional[List[Dict[str, Any]]] = None,
        rem_statuses: Optional[List[str]] = None
    ) -> None:
        """
        Update a contact.

        Args:
            contact_id: Contact ID to update
            user_id: Updating user ID
            name-email: Fields to update (None = no change)
            auth_info: New auth info (None = no change)
            add_statuses: Statuses to add
            rem_statuses: Statuses to remove
        """
        roid = await self.get_roid(contact_id)
        if not roid:
            raise ValueError(f"Contact not found: {contact_id}")

        now = datetime.utcnow()

        # Build contact update
        contact_updates = []
        contact_params = {"contact_id": contact_id}

        field_map = {
            "name": ("CON_NAME", name),
            "org": ("CON_ORG", org),
            "street1": ("CON_STREET1", street1),
            "street2": ("CON_STREET2", street2),
            "street3": ("CON_STREET3", street3),
            "city": ("CON_CITY", city),
            "state": ("CON_STATE", state),
            "postcode": ("CON_POSTCODE", postcode),
            "country": ("CON_COUNTRY", country),
            "phone": ("CON_PHONE", phone),
            "phone_ext": ("CON_PHONE_EXT", phone_ext),
            "fax": ("CON_FAX", fax),
            "fax_ext": ("CON_FAX_EXT", fax_ext),
            "email": ("CON_EMAIL", email),
        }

        for key, (col, val) in field_map.items():
            if val is not None:
                contact_updates.append(f"{col} = :{key}")
                contact_params[key] = val

        if contact_updates:
            sql = f"UPDATE CONTACTS SET {', '.join(contact_updates)} WHERE CON_UID = :contact_id"
            await self.pool.execute(sql, contact_params, commit=False)

        # Update registry object
        obj_updates = ["OBJ_UPDATE_DATE = :update_date", "OBJ_UPDATE_USER_ID = :user_id"]
        obj_params = {"roid": roid, "update_date": now, "user_id": user_id}

        if auth_info is not None:
            obj_updates.append("OBJ_PASSWORD = :auth_info")
            obj_params["auth_info"] = auth_info

        sql = f"UPDATE REGISTRY_OBJECTS SET {', '.join(obj_updates)} WHERE OBJ_ROID = :roid"
        await self.pool.execute(sql, obj_params, commit=False)

        # Handle status changes
        if rem_statuses:
            for status in rem_statuses:
                await self._remove_status(roid, status, commit=False)

        if add_statuses:
            for status in add_statuses:
                await self._add_status(
                    roid,
                    status["s"],
                    status.get("lang"),
                    status.get("reason"),
                    commit=False
                )

        # Commit transaction
        async with self.pool.acquire() as conn:
            await conn.commit()

        logger.info(f"Updated contact {contact_id}")

    # ========================================================================
    # Delete Operations
    # ========================================================================

    async def delete(self, contact_id: str) -> None:
        """
        Delete a contact.

        Args:
            contact_id: Contact ID to delete

        Raises:
            ValueError: If contact is in use
        """
        roid = await self.get_roid(contact_id)
        if not roid:
            raise ValueError(f"Contact not found: {contact_id}")

        # Check if in use
        in_use, reason = await self.is_in_use(contact_id)
        if in_use:
            raise ValueError(f"Cannot delete contact: {reason}")

        # Delete statuses
        await self.pool.execute(
            "DELETE FROM EPP_CONTACT_STATUSES WHERE ECS_ROID = :roid",
            {"roid": roid},
            commit=False
        )

        # Delete contact
        await self.pool.execute(
            "DELETE FROM CONTACTS WHERE CON_ROID = :roid",
            {"roid": roid},
            commit=False
        )

        # Delete registry object
        await self.pool.execute(
            "DELETE FROM REGISTRY_OBJECTS WHERE OBJ_ROID = :roid",
            {"roid": roid},
            commit=False
        )

        # Commit transaction
        async with self.pool.acquire() as conn:
            await conn.commit()

        logger.info(f"Deleted contact {contact_id}")

    # ========================================================================
    # Status Operations
    # ========================================================================

    async def _add_status(
        self,
        roid: str,
        status: str,
        lang: Optional[str] = None,
        reason: Optional[str] = None,
        commit: bool = True
    ) -> None:
        """Add a status to contact."""
        sql = """
            INSERT INTO EPP_CONTACT_STATUSES (ECS_ROID, ECS_STATUS, ECS_LANG, ECS_REASON)
            VALUES (:roid, :status, :lang, :reason)
        """
        await self.pool.execute(sql, {
            "roid": roid,
            "status": status,
            "lang": lang,
            "reason": reason
        }, commit=commit)

    async def _remove_status(
        self,
        roid: str,
        status: str,
        commit: bool = True
    ) -> None:
        """Remove a status from contact."""
        sql = "DELETE FROM EPP_CONTACT_STATUSES WHERE ECS_ROID = :roid AND ECS_STATUS = :status"
        await self.pool.execute(sql, {"roid": roid, "status": status}, commit=commit)

    async def has_status(self, contact_id: str, status: str) -> bool:
        """Check if contact has a specific status."""
        roid = await self.get_roid(contact_id)
        if not roid:
            return False

        sql = """
            SELECT COUNT(*) FROM EPP_CONTACT_STATUSES
            WHERE ECS_ROID = :roid AND ECS_STATUS = :status
        """
        count = await self.pool.query_value(sql, {"roid": roid, "status": status})
        return int(count) > 0 if count else False

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def _format_date(self, dt: Any) -> Optional[str]:
        """Format date/datetime for EPP response."""
        if dt is None:
            return None
        if isinstance(dt, datetime):
            return dt.strftime("%Y-%m-%dT%H:%M:%S.0Z")
        if isinstance(dt, date):
            return datetime.combine(dt, datetime.min.time()).strftime("%Y-%m-%dT%H:%M:%S.0Z")
        return str(dt)


# Global repository instance
_contact_repo: Optional[ContactRepository] = None


async def get_contact_repo() -> ContactRepository:
    """Get or create global contact repository."""
    global _contact_repo
    if _contact_repo is None:
        pool = await get_pool()
        _contact_repo = ContactRepository(pool)
    return _contact_repo
