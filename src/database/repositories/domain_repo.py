"""
Domain Repository

Handles domain-related database read operations including:
- Domain info retrieval
- Authorization verification
- ROID lookup
- Rate lookup
- AR extension operations (undelete, unrenew, policy delete/undelete)

Note: Domain create/update/delete/renew/transfer operations are handled
by ARI PL/SQL stored procedures via plsql_caller.py.
"""

import logging
from datetime import datetime, date, timedelta
from dateutil.relativedelta import relativedelta
from typing import Any, Dict, List, Optional
from decimal import Decimal

from src.database.connection import get_pool, DatabasePool

logger = logging.getLogger("epp.database.domain")


class DomainRepository:
    """
    Repository for domain read operations and AR extension methods.

    All queries use parameterized statements to prevent SQL injection.
    Write operations (create/update/delete/renew/transfer) are handled
    by PL/SQL stored procedures.
    """

    def __init__(self, pool: DatabasePool):
        """Initialize with database pool."""
        self.pool = pool

    # ========================================================================
    # Info Operations
    # ========================================================================

    async def get_by_name(
        self,
        domain_name: str,
        include_auth: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Get domain by name with all related data.

        Args:
            domain_name: Full domain name
            include_auth: Whether to include auth info (requires authorization)

        Returns:
            Domain data dict or None
        """
        domain_name = domain_name.lower()

        # Main domain query
        sql = """
            SELECT
                d.DOM_ROID,
                d.DOM_NAME,
                d.DOM_LABEL,
                d.DOM_ZONE,
                d.DOM_REGISTRANT_ROID,
                d.DOM_DNS_QUALIFIED,
                d.DOM_DNS_HOLD,
                o.OBJ_STATUS,
                o.OBJ_PASSWORD,
                o.OBJ_CREATE_DATE,
                o.OBJ_CREATE_USER_ID,
                o.OBJ_MANAGE_ACCOUNT_ID,
                o.OBJ_UPDATE_DATE,
                o.OBJ_UPDATE_USER_ID,
                o.OBJ_TRANSFER_DATE,
                dr.DRE_EXPIRE_DATE,
                cr_user.USR_USERNAME AS CR_USERNAME,
                up_user.USR_USERNAME AS UP_USERNAME,
                acc.ACC_CLIENT_ID AS CL_ID
            FROM DOMAINS d
            JOIN REGISTRY_OBJECTS o ON d.DOM_ROID = o.OBJ_ROID
            LEFT JOIN DOMAIN_REGISTRATIONS dr ON d.DOM_REGISTRATION_ID = dr.DRE_ID
            LEFT JOIN USERS cr_user ON o.OBJ_CREATE_USER_ID = cr_user.USR_ID
            LEFT JOIN USERS up_user ON o.OBJ_UPDATE_USER_ID = up_user.USR_ID
            LEFT JOIN ACCOUNTS acc ON o.OBJ_MANAGE_ACCOUNT_ID = acc.ACC_ID
            WHERE LOWER(d.DOM_NAME) = :domain_name
        """

        row = await self.pool.query_one(sql, {"domain_name": domain_name})

        if not row:
            return None

        roid = row["DOM_ROID"]

        # Get statuses
        statuses = await self._get_domain_statuses(roid)

        # Get contacts
        contacts = await self._get_domain_contacts(roid)

        # Get registrant contact ID
        registrant_id = await self._get_contact_uid(row["DOM_REGISTRANT_ROID"])

        # Get nameservers
        nameservers = await self._get_domain_nameservers(roid)

        # Get subordinate hosts
        hosts = await self._get_subordinate_hosts(roid)

        # Build response
        domain_data = {
            "name": row["DOM_NAME"],
            "roid": roid,
            "statuses": statuses,
            "registrant": registrant_id,
            "contacts": contacts,
            "nameservers": nameservers,
            "hosts": hosts,
            "clID": row["CL_ID"] or "",
            "crID": row["CR_USERNAME"],
            "crDate": self._format_date(row["OBJ_CREATE_DATE"]),
            "upID": row["UP_USERNAME"],
            "upDate": self._format_date(row["OBJ_UPDATE_DATE"]),
            "exDate": self._format_date(row["DRE_EXPIRE_DATE"]),
            "trDate": self._format_date(row["OBJ_TRANSFER_DATE"]),
            "authInfo": row["OBJ_PASSWORD"] if include_auth else None,
            # Additional fields for internal use
            "_account_id": row["OBJ_MANAGE_ACCOUNT_ID"],
            "_zone": row["DOM_ZONE"],
        }

        return domain_data

    async def _get_domain_statuses(self, roid: str) -> List[Dict[str, Any]]:
        """Get EPP statuses for domain."""
        sql = """
            SELECT EDS_STATUS, EDS_LANG, EDS_REASON
            FROM EPP_DOMAIN_STATUSES
            WHERE EDS_ROID = :roid
        """
        rows = await self.pool.query(sql, {"roid": roid})

        statuses = []
        for row in rows:
            statuses.append({
                "s": row["EDS_STATUS"],
                "lang": row.get("EDS_LANG"),
                "reason": row.get("EDS_REASON")
            })

        # Add default status if none
        if not statuses:
            statuses.append({"s": "ok"})

        return statuses

    async def _get_domain_contacts(self, roid: str) -> List[Dict[str, Any]]:
        """Get contacts associated with domain."""
        sql = """
            SELECT dc.DCN_TYPE, c.CON_UID
            FROM DOMAIN_CONTACTS dc
            JOIN CONTACTS c ON dc.DCN_CONTACT_ROID = c.CON_ROID
            WHERE dc.DCN_DOMAIN_ROID = :roid
        """
        rows = await self.pool.query(sql, {"roid": roid})

        contacts = []
        for row in rows:
            contacts.append({
                "id": row["CON_UID"],
                "type": row["DCN_TYPE"]
            })

        return contacts

    async def _get_domain_nameservers(self, roid: str) -> List[str]:
        """Get nameservers for domain."""
        sql = """
            SELECT h.HOS_NAME
            FROM DOMAIN_NAMESERVERS dn
            JOIN HOSTS h ON dn.DNS_HOST_ROID = h.HOS_ROID
            WHERE dn.DNS_DOMAIN_ROID = :roid
            ORDER BY h.HOS_NAME
        """
        rows = await self.pool.query(sql, {"roid": roid})
        return [row["HOS_NAME"] for row in rows]

    async def _get_subordinate_hosts(self, roid: str) -> List[str]:
        """Get subordinate hosts (glue records) for domain."""
        sql = """
            SELECT HOS_NAME
            FROM HOSTS
            WHERE HOS_DOMAIN_ROID = :roid
            ORDER BY HOS_NAME
        """
        rows = await self.pool.query(sql, {"roid": roid})
        return [row["HOS_NAME"] for row in rows]

    async def _get_contact_uid(self, contact_roid: str) -> Optional[str]:
        """Get contact UID by ROID."""
        if not contact_roid:
            return None
        sql = "SELECT CON_UID FROM CONTACTS WHERE CON_ROID = :roid"
        return await self.pool.query_value(sql, {"roid": contact_roid})

    # ========================================================================
    # Authorization Operations
    # ========================================================================

    async def verify_auth_info(
        self,
        domain_name: str,
        auth_info: str
    ) -> bool:
        """
        Verify domain auth info password.

        Args:
            domain_name: Domain name
            auth_info: Auth info to verify

        Returns:
            True if auth info matches
        """
        sql = """
            SELECT o.OBJ_PASSWORD
            FROM DOMAINS d
            JOIN REGISTRY_OBJECTS o ON d.DOM_ROID = o.OBJ_ROID
            WHERE LOWER(d.DOM_NAME) = :domain_name
        """
        stored = await self.pool.query_value(sql, {"domain_name": domain_name.lower()})

        if not stored:
            return False

        # Simple comparison - in production use timing-safe compare
        return stored == auth_info

    # ========================================================================
    # Rate Lookup
    # ========================================================================

    async def get_rate(
        self,
        zone: str,
        period: int,
        unit: str = "y"
    ) -> Optional[Decimal]:
        """
        Get registration/renewal rate for zone and period.

        Args:
            zone: Zone name
            period: Period value
            unit: Period unit (y=year, m=month)

        Returns:
            Rate amount or None
        """
        sql = """
            SELECT RAT_AMOUNT
            FROM RATES
            WHERE RAT_ZONE = :zone
              AND RAT_PERIOD = :period
              AND RAT_UNIT = :unit
              AND RAT_START_DATE <= :today
              AND (RAT_END_DATE IS NULL OR RAT_END_DATE > :today)
        """
        result = await self.pool.query_value(sql, {
            "zone": zone.lower(),
            "period": period,
            "unit": unit,
            "today": date.today()
        })
        return Decimal(str(result)) if result else None

    # ========================================================================
    # ROID Lookup
    # ========================================================================

    async def get_roid(self, domain_name: str) -> Optional[str]:
        """Get ROID for domain."""
        sql = "SELECT DOM_ROID FROM DOMAINS WHERE LOWER(DOM_NAME) = :domain_name"
        return await self.pool.query_value(sql, {"domain_name": domain_name.lower()})

    # ========================================================================
    # AR Extension Methods (Undelete, Unrenew, PolicyDelete, PolicyUndelete)
    # ========================================================================

    async def undelete(
        self,
        domain_roid: str,
        user_id: int
    ) -> bool:
        """
        Restore a deleted domain from redemption grace period.

        Args:
            domain_roid: Domain ROID
            user_id: User performing the undelete

        Returns:
            True if successful
        """
        now = datetime.utcnow()

        async with self.pool.transaction() as conn:
            # Remove pendingDelete and redemptionPeriod statuses
            await conn.execute(
                """DELETE FROM EPP_DOMAIN_STATUSES
                   WHERE EDS_ROID = :roid
                   AND EDS_STATUS IN ('pendingDelete', 'redemptionPeriod')""",
                {"roid": domain_roid}
            )

            # Check if any statuses remain, if not add 'ok'
            status_count = await conn.query_value(
                "SELECT COUNT(*) FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid",
                {"roid": domain_roid}
            )
            if status_count == 0:
                await conn.execute(
                    "INSERT INTO EPP_DOMAIN_STATUSES (EDS_ROID, EDS_STATUS) VALUES (:roid, 'ok')",
                    {"roid": domain_roid}
                )

            # Update domain record - restore active status and clear delete date
            # DOM_ACTIVE_INDICATOR = '0' marks domain as active
            await conn.execute(
                """UPDATE DOMAINS
                   SET DOM_DELETE_DATE = NULL,
                       DOM_ACTIVE_INDICATOR = '0'
                   WHERE DOM_ROID = :roid""",
                {"roid": domain_roid}
            )

            # Update registry object with Registered status
            await conn.execute(
                """UPDATE REGISTRY_OBJECTS
                   SET OBJ_STATUS = 'Registered',
                       OBJ_UPDATE_DATE = :update_date,
                       OBJ_UPDATE_USER_ID = :user_id
                   WHERE OBJ_ROID = :roid""",
                {"roid": domain_roid, "update_date": now, "user_id": user_id}
            )

        return True

    async def unrenew(
        self,
        domain_roid: str,
        user_id: int,
        account_id: int
    ) -> Dict[str, Any]:
        """
        Cancel a pending renewal and revert expiry date.

        Args:
            domain_roid: Domain ROID
            user_id: User performing the unrenew
            account_id: Account to refund

        Returns:
            Dict with exDate (reverted expiration date)
        """
        now = datetime.utcnow()

        # Get the last renewal transaction to determine how much to refund
        last_renewal = await self.pool.query_one(
            """SELECT TRANSACTION_ID, PERIOD, PERIOD_UNIT, AMOUNT, OLD_EXPIRY_DATE
               FROM DOMAIN_RENEWALS
               WHERE DOM_ROID = :roid
               AND RENEWAL_DATE > :cutoff
               ORDER BY RENEWAL_DATE DESC
               FETCH FIRST 1 ROW ONLY""",
            {"roid": domain_roid, "cutoff": now - timedelta(days=30)}
        )

        if not last_renewal:
            raise Exception("No recent renewal found to reverse")

        old_expiry_date = last_renewal.get("OLD_EXPIRY_DATE")
        if not old_expiry_date:
            raise Exception("Original expiry date not recorded")

        async with self.pool.transaction() as conn:
            # Revert expiry date
            await conn.execute(
                """UPDATE DOMAINS
                   SET DOM_EXPIRY_DATE = :old_expiry,
                       DOM_UPDATE_DATE = :update_date,
                       DOM_UPDATE_USER_ID = :user_id
                   WHERE DOM_ROID = :roid""",
                {"roid": domain_roid, "old_expiry": old_expiry_date,
                 "update_date": now, "user_id": user_id}
            )

            # Refund the renewal fee
            amount = last_renewal.get("AMOUNT", Decimal("0"))
            if amount > 0:
                await conn.execute(
                    """INSERT INTO ACCOUNT_TRANSACTIONS
                       (TRANSACTION_ID, ACCOUNT_ID, TRANSACTION_TYPE, AMOUNT,
                        DESCRIPTION, TRANSACTION_DATE)
                       VALUES (ACCOUNT_TXN_SEQ.NEXTVAL, :account_id, 'UNRENEW_REFUND',
                               :amount, :description, SYSDATE)""",
                    {"account_id": account_id, "amount": amount,
                     "description": f"Unrenew refund for domain {domain_roid}"}
                )

                await conn.execute(
                    "UPDATE ACCOUNTS SET BALANCE = BALANCE + :amount WHERE ACCOUNT_ID = :account_id",
                    {"amount": amount, "account_id": account_id}
                )

            # Mark the renewal as reversed
            await conn.execute(
                "UPDATE DOMAIN_RENEWALS SET REVERSED = 'Y' WHERE TRANSACTION_ID = :txn_id",
                {"txn_id": last_renewal.get("TRANSACTION_ID")}
            )

        # Format return date
        return {"exDate": self._format_date(old_expiry_date)}

    async def policy_delete(
        self,
        domain_roid: str,
        user_id: int,
        reason: Optional[str] = None
    ) -> bool:
        """
        Delete a domain for policy violation.

        This deletes immediately without grace period.

        Args:
            domain_roid: Domain ROID
            user_id: User performing the delete
            reason: Reason for policy deletion

        Returns:
            True if successful
        """
        now = datetime.utcnow()

        async with self.pool.transaction() as conn:
            # Log the policy deletion
            await conn.execute(
                """INSERT INTO DOMAIN_POLICY_ACTIONS
                   (ACTION_ID, DOM_ROID, ACTION_TYPE, REASON, ACTION_DATE, USER_ID)
                   VALUES (POLICY_ACTION_SEQ.NEXTVAL, :roid, 'POLICY_DELETE',
                           :reason, :action_date, :user_id)""",
                {"roid": domain_roid, "reason": reason, "action_date": now, "user_id": user_id}
            )

            # Update domain with immediate delete
            # DOM_ACTIVE_INDICATOR = ROID marks domain as inactive
            await conn.execute(
                """UPDATE DOMAINS
                   SET DOM_DELETE_DATE = :delete_date,
                       DOM_ACTIVE_INDICATOR = :roid
                   WHERE DOM_ROID = :roid""",
                {"roid": domain_roid, "delete_date": now}
            )

            # Update registry object
            await conn.execute(
                """UPDATE REGISTRY_OBJECTS
                   SET OBJ_STATUS = 'Policy Deleted',
                       OBJ_UPDATE_DATE = :update_date,
                       OBJ_UPDATE_USER_ID = :user_id
                   WHERE OBJ_ROID = :roid""",
                {"roid": domain_roid, "update_date": now, "user_id": user_id}
            )

            # Set policy deleted status
            await conn.execute(
                "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid",
                {"roid": domain_roid}
            )
            await conn.execute(
                "INSERT INTO EPP_DOMAIN_STATUSES (EDS_ROID, EDS_STATUS) VALUES (:roid, 'serverDeleteProhibited')",
                {"roid": domain_roid}
            )

        return True

    async def policy_undelete(
        self,
        domain_roid: str,
        user_id: int
    ) -> bool:
        """
        Restore a domain that was deleted for policy violation.

        Args:
            domain_roid: Domain ROID
            user_id: User performing the restore

        Returns:
            True if successful
        """
        now = datetime.utcnow()

        async with self.pool.transaction() as conn:
            # Log the policy undelete
            await conn.execute(
                """INSERT INTO DOMAIN_POLICY_ACTIONS
                   (ACTION_ID, DOM_ROID, ACTION_TYPE, ACTION_DATE, USER_ID)
                   VALUES (POLICY_ACTION_SEQ.NEXTVAL, :roid, 'POLICY_UNDELETE',
                           :action_date, :user_id)""",
                {"roid": domain_roid, "action_date": now, "user_id": user_id}
            )

            # Clear delete date and restore active status
            # DOM_ACTIVE_INDICATOR = '0' marks domain as active
            await conn.execute(
                """UPDATE DOMAINS
                   SET DOM_DELETE_DATE = NULL,
                       DOM_ACTIVE_INDICATOR = '0'
                   WHERE DOM_ROID = :roid""",
                {"roid": domain_roid}
            )

            # Update registry object
            await conn.execute(
                """UPDATE REGISTRY_OBJECTS
                   SET OBJ_STATUS = 'Registered',
                       OBJ_UPDATE_DATE = :update_date,
                       OBJ_UPDATE_USER_ID = :user_id
                   WHERE OBJ_ROID = :roid""",
                {"roid": domain_roid, "update_date": now, "user_id": user_id}
            )

            # Reset to ok status
            await conn.execute(
                "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid",
                {"roid": domain_roid}
            )
            await conn.execute(
                "INSERT INTO EPP_DOMAIN_STATUSES (EDS_ROID, EDS_STATUS) VALUES (:roid, 'ok')",
                {"roid": domain_roid}
            )

        return True

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
_domain_repo: Optional[DomainRepository] = None


async def get_domain_repo() -> DomainRepository:
    """Get or create global domain repository."""
    global _domain_repo
    if _domain_repo is None:
        pool = await get_pool()
        _domain_repo = DomainRepository(pool)
    return _domain_repo
