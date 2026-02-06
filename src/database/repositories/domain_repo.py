"""
Domain Repository

Handles all domain-related database operations including:
- Availability checks
- Domain info retrieval
- Domain creation, update, deletion
- Renewal and transfer operations
"""

import logging
from datetime import datetime, date, timedelta
from dateutil.relativedelta import relativedelta
from typing import Any, Dict, List, Optional, Tuple
from decimal import Decimal

from src.database.connection import get_pool, DatabasePool
from src.database.models import DomainInfo

logger = logging.getLogger("epp.database.domain")


class DomainRepository:
    """
    Repository for domain operations.

    All queries use parameterized statements to prevent SQL injection.
    """

    def __init__(self, pool: DatabasePool):
        """Initialize with database pool."""
        self.pool = pool

    # ========================================================================
    # Check Operations
    # ========================================================================

    async def check_available(self, domain_name: str) -> Tuple[bool, Optional[str]]:
        """
        Check if domain is available for registration.

        Args:
            domain_name: Full domain name (e.g., "example.ae")

        Returns:
            Tuple of (is_available, reason_if_not)
        """
        domain_name = domain_name.lower()

        # Check if domain exists
        sql = """
            SELECT d.DOM_ROID, o.OBJ_STATUS
            FROM DOMAINS d
            JOIN REGISTRY_OBJECTS o ON d.DOM_ROID = o.OBJ_ROID
            WHERE LOWER(d.DOM_NAME) = :domain_name
        """

        row = await self.pool.query_one(sql, {"domain_name": domain_name})

        if row:
            status = row.get("OBJ_STATUS", "")
            if "pendingDelete" in status:
                return False, "In pending delete"
            return False, "In use"

        # Check if domain is reserved (would need RESERVED_DOMAINS table)
        # For now, assume not reserved
        return True, None

    async def check_multiple(
        self,
        domain_names: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Check availability of multiple domains.

        Args:
            domain_names: List of domain names to check

        Returns:
            List of {name, avail, reason} dicts
        """
        results = []
        for name in domain_names:
            avail, reason = await self.check_available(name)
            results.append({
                "name": name.lower(),
                "avail": avail,
                "reason": reason
            })
        return results

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

    async def get_by_roid(self, roid: str) -> Optional[Dict[str, Any]]:
        """
        Get domain by ROID.

        Args:
            roid: Registry Object ID

        Returns:
            Domain data dict or None
        """
        sql = "SELECT DOM_NAME FROM DOMAINS WHERE DOM_ROID = :roid"
        row = await self.pool.query_one(sql, {"roid": roid})

        if not row:
            return None

        return await self.get_by_name(row["DOM_NAME"])

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
    # Zone Operations
    # ========================================================================

    async def get_zone(self, zone_name: str) -> Optional[Dict[str, Any]]:
        """
        Get zone configuration.

        Args:
            zone_name: Zone name (e.g., "ae", "com.ae")

        Returns:
            Zone configuration dict or None
        """
        sql = """
            SELECT ZON_ZONE, ZON_ID, ZON_STATUS, ZON_FORMAT,
                   ZON_CREATE_MIN_YEARS, ZON_CREATE_MAX_YEARS,
                   ZON_MAX_EXPIRY_YEARS, ZON_TRANSFER_PENDING_DAYS,
                   ZON_DELETE_CANCEL_DAYS, ZON_RENEW_BEFORE_EXPIRE_DAYS,
                   ZON_MIN_DNS_TO_DELEGATE
            FROM ZONES
            WHERE ZON_ZONE = :zone_name
        """
        return await self.pool.query_one(sql, {"zone_name": zone_name.lower()})

    async def get_zone_for_domain(self, domain_name: str) -> Optional[Dict[str, Any]]:
        """
        Get zone configuration for a domain name.

        Args:
            domain_name: Full domain name

        Returns:
            Zone configuration dict or None
        """
        # Extract zone from domain name
        parts = domain_name.lower().split(".")
        if len(parts) < 2:
            return None

        # Try longest match first (e.g., "com.ae" before "ae")
        for i in range(len(parts) - 1):
            zone_name = ".".join(parts[i + 1:])
            zone = await self.get_zone(zone_name)
            if zone:
                return zone

        return None

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

    async def get_sponsoring_account(self, domain_name: str) -> Optional[int]:
        """
        Get account ID that sponsors the domain.

        Args:
            domain_name: Domain name

        Returns:
            Account ID or None
        """
        sql = """
            SELECT o.OBJ_MANAGE_ACCOUNT_ID
            FROM DOMAINS d
            JOIN REGISTRY_OBJECTS o ON d.DOM_ROID = o.OBJ_ROID
            WHERE LOWER(d.DOM_NAME) = :domain_name
        """
        result = await self.pool.query_value(sql, {"domain_name": domain_name.lower()})
        return int(result) if result else None

    # ========================================================================
    # Transfer Query Operations
    # ========================================================================

    async def get_transfer_info(self, domain_name: str) -> Optional[Dict[str, Any]]:
        """
        Get pending transfer info for domain.

        Args:
            domain_name: Domain name

        Returns:
            Transfer info dict or None
        """
        sql = """
            SELECT t.TRX_ID, t.TRX_STATUS, t.TRX_REQUEST_DATE,
                   t.TRX_ACCEPT_DATE, t.TRX_PERIOD, t.TRX_UNIT,
                   req_acc.ACC_CLIENT_ID AS RE_ID,
                   from_acc.ACC_CLIENT_ID AS AC_ID
            FROM TRANSFERS t
            JOIN DOMAINS d ON t.TRX_ROID = d.DOM_ROID
            JOIN ACCOUNTS req_acc ON t.TRX_TO_ACCOUNT_ID = req_acc.ACC_ID
            JOIN ACCOUNTS from_acc ON t.TRX_FROM_ACCOUNT_ID = from_acc.ACC_ID
            WHERE LOWER(d.DOM_NAME) = :domain_name
              AND t.TRX_STATUS = 'pending'
        """
        return await self.pool.query_one(sql, {"domain_name": domain_name.lower()})

    # ========================================================================
    # Create Operations
    # ========================================================================

    async def create(
        self,
        domain_name: str,
        roid: str,
        account_id: int,
        user_id: int,
        registrant_id: str,
        auth_info: str,
        period: int = 1,
        unit: str = "y",
        contacts: Optional[List[Dict[str, str]]] = None,
        nameservers: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Create a new domain registration.

        Args:
            domain_name: Full domain name
            roid: Pre-generated ROID
            account_id: Sponsoring account ID
            user_id: Creating user ID
            registrant_id: Registrant contact ID
            auth_info: Authorization password
            period: Registration period
            unit: Period unit (y=years, m=months)
            contacts: Optional list of {id, type} dicts
            nameservers: Optional list of nameserver hostnames

        Returns:
            Created domain data dict

        Raises:
            Exception: If domain already exists or creation fails
        """
        domain_name = domain_name.lower()
        now = datetime.utcnow()

        # Check availability
        avail, reason = await self.check_available(domain_name)
        if not avail:
            raise Exception(f"Domain {domain_name} not available: {reason}")

        # Extract zone and label
        zone = self.extract_zone(domain_name)
        label = self.extract_label(domain_name)

        # Get zone configuration
        zone_config = await self.get_zone(zone)
        if not zone_config:
            raise Exception(f"Zone {zone} not found")

        # Validate period
        min_years = zone_config.get("ZON_CREATE_MIN_YEARS", 1)
        max_years = zone_config.get("ZON_CREATE_MAX_YEARS", 10)
        period_years = period if unit == "y" else period / 12

        if period_years < min_years or period_years > max_years:
            raise Exception(f"Period must be between {min_years} and {max_years} years")

        # Calculate expiry date
        if unit == "y":
            expiry_date = now + relativedelta(years=period)
        else:
            expiry_date = now + relativedelta(months=period)

        # Get registrant ROID
        registrant_roid = await self._get_contact_roid(registrant_id)
        if not registrant_roid:
            raise Exception(f"Registrant contact {registrant_id} not found")

        async with self.pool.transaction() as conn:
            # Insert into REGISTRY_OBJECTS
            obj_sql = """
                INSERT INTO REGISTRY_OBJECTS (
                    OBJ_ROID, OBJ_TYPE, OBJ_STATUS, OBJ_PASSWORD,
                    OBJ_CREATE_DATE, OBJ_CREATE_USER_ID,
                    OBJ_MANAGE_ACCOUNT_ID, OBJ_LOCKED
                ) VALUES (
                    :roid, 'Domain', 'Registered', :auth_info,
                    :create_date, :user_id,
                    :account_id, 'N'
                )
            """
            await conn.execute(obj_sql, {
                "roid": roid,
                "auth_info": auth_info,
                "create_date": now,
                "user_id": user_id,
                "account_id": account_id
            })

            # Insert into DOMAINS first (without registration ID due to circular FK)
            # DOM_CANONICAL_FORM and DOM_ACTIVE_INDICATOR are NOT NULL
            dom_sql = """
                INSERT INTO DOMAINS (
                    DOM_ROID, DOM_NAME, DOM_LABEL, DOM_CANONICAL_FORM,
                    DOM_ZONE, DOM_REGISTRANT_ROID, DOM_REGISTRATION_ID,
                    DOM_DNS_QUALIFIED, DOM_DNS_HOLD, DOM_ACTIVE_INDICATOR
                ) VALUES (
                    :roid, :domain_name, :label, :canonical_form,
                    :zone, :registrant_roid, NULL,
                    'N', 'N', :roid
                )
            """
            await conn.execute(dom_sql, {
                "roid": roid,
                "domain_name": domain_name,
                "label": label,
                "canonical_form": domain_name,
                "zone": zone,
                "registrant_roid": registrant_roid
            })

            # Create domain registration record (now DOM_ROID exists for FK)
            reg_id = await conn.get_next_sequence("DRE_ID_SEQ")
            reg_sql = """
                INSERT INTO DOMAIN_REGISTRATIONS (
                    DRE_ID, DRE_ROID, DRE_SEQ, DRE_PERIOD, DRE_UNIT,
                    DRE_REQUEST_DATE, DRE_START_DATE, DRE_EXPIRE_DATE, DRE_STATUS
                ) VALUES (
                    :reg_id, :roid, 1, :period, :unit,
                    :request_date, :start_date, :expire_date, 'approved'
                )
            """
            await conn.execute(reg_sql, {
                "reg_id": reg_id,
                "roid": roid,
                "period": period,
                "unit": unit,
                "request_date": now,
                "start_date": now,
                "expire_date": expiry_date
            })

            # Update DOMAINS with registration ID
            update_dom_sql = """
                UPDATE DOMAINS SET DOM_REGISTRATION_ID = :reg_id
                WHERE DOM_ROID = :roid
            """
            await conn.execute(update_dom_sql, {
                "reg_id": reg_id,
                "roid": roid
            })

            # Add contacts
            if contacts:
                for contact in contacts:
                    contact_roid = await self._get_contact_roid(contact["id"], conn)
                    if contact_roid:
                        contact_sql = """
                            INSERT INTO DOMAIN_CONTACTS (
                                DCN_DOMAIN_ROID, DCN_CONTACT_ROID, DCN_TYPE
                            ) VALUES (
                                :domain_roid, :contact_roid, :contact_type
                            )
                        """
                        await conn.execute(contact_sql, {
                            "domain_roid": roid,
                            "contact_roid": contact_roid,
                            "contact_type": contact["type"]
                        })
                    else:
                        logger.warning(f"Contact {contact['id']} not found, skipping")

            # Add nameservers
            if nameservers:
                for ns in nameservers:
                    host_roid = await self._get_host_roid(ns, conn)
                    if host_roid:
                        ns_sql = """
                            INSERT INTO DOMAIN_NAMESERVERS (
                                DNS_DOMAIN_ROID, DNS_HOST_ROID
                            ) VALUES (
                                :domain_roid, :host_roid
                            )
                        """
                        await conn.execute(ns_sql, {
                            "domain_roid": roid,
                            "host_roid": host_roid
                        })
                    else:
                        logger.warning(f"Host {ns} not found, skipping")

            # Add default 'ok' status
            status_sql = """
                INSERT INTO EPP_DOMAIN_STATUSES (
                    EDS_ROID, EDS_STATUS
                ) VALUES (
                    :roid, 'ok'
                )
            """
            await conn.execute(status_sql, {"roid": roid})

        logger.info(f"Created domain: {domain_name} (ROID: {roid})")

        return await self.get_by_name(domain_name)

    async def _get_contact_roid(self, contact_id: str, conn=None) -> Optional[str]:
        """Get ROID for contact by UID.

        Args:
            contact_id: Contact UID
            conn: Optional transaction connection (uses pool if None)
        """
        sql = "SELECT CON_ROID FROM CONTACTS WHERE CON_UID = :contact_id"
        if conn:
            result = await conn.query_one(sql, {"contact_id": contact_id})
            return result["CON_ROID"] if result else None
        return await self.pool.query_value(sql, {"contact_id": contact_id})

    async def _get_host_roid(self, hostname: str, conn=None) -> Optional[str]:
        """Get ROID for host by name.

        Args:
            hostname: Host FQDN
            conn: Optional transaction connection (uses pool if None)
        """
        sql = "SELECT HOS_ROID FROM HOSTS WHERE LOWER(HOS_NAME) = :hostname"
        if conn:
            result = await conn.query_one(sql, {"hostname": hostname.lower()})
            return result["HOS_ROID"] if result else None
        return await self.pool.query_value(sql, {"hostname": hostname.lower()})

    # ========================================================================
    # Update Operations
    # ========================================================================

    async def update(
        self,
        domain_name: str,
        user_id: int,
        registrant_id: Optional[str] = None,
        auth_info: Optional[str] = None,
        add_contacts: Optional[List[Dict[str, str]]] = None,
        rem_contacts: Optional[List[Dict[str, str]]] = None,
        add_nameservers: Optional[List[str]] = None,
        rem_nameservers: Optional[List[str]] = None,
        add_statuses: Optional[List[str]] = None,
        rem_statuses: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Update an existing domain.

        Args:
            domain_name: Domain name
            user_id: Updating user ID
            registrant_id: New registrant contact ID
            auth_info: New authorization password
            add_contacts: Contacts to add [{id, type}]
            rem_contacts: Contacts to remove [{id, type}]
            add_nameservers: Nameservers to add
            rem_nameservers: Nameservers to remove
            add_statuses: Statuses to add
            rem_statuses: Statuses to remove

        Returns:
            Updated domain data dict

        Raises:
            Exception: If domain not found or update fails
        """
        domain_name = domain_name.lower()
        now = datetime.utcnow()

        # Get current domain
        domain = await self.get_by_name(domain_name)
        if not domain:
            raise Exception(f"Domain {domain_name} not found")

        roid = domain["roid"]

        # Check for update prohibited status
        statuses = [s["s"] for s in domain["statuses"]]
        if "clientUpdateProhibited" in statuses or "serverUpdateProhibited" in statuses:
            raise Exception("Domain update prohibited by status")

        async with self.pool.transaction() as conn:
            # Update REGISTRY_OBJECTS
            update_fields = ["OBJ_UPDATE_DATE = :update_date", "OBJ_UPDATE_USER_ID = :user_id"]
            params = {"update_date": now, "user_id": user_id, "roid": roid}

            if auth_info:
                update_fields.append("OBJ_PASSWORD = :auth_info")
                params["auth_info"] = auth_info

            obj_sql = f"""
                UPDATE REGISTRY_OBJECTS
                SET {', '.join(update_fields)}
                WHERE OBJ_ROID = :roid
            """
            await conn.execute(obj_sql, params)

            # Update registrant
            if registrant_id:
                registrant_roid = await self._get_contact_roid(registrant_id, conn)
                if not registrant_roid:
                    raise Exception(f"Registrant contact {registrant_id} not found")

                await conn.execute(
                    "UPDATE DOMAINS SET DOM_REGISTRANT_ROID = :registrant_roid WHERE DOM_ROID = :roid",
                    {"registrant_roid": registrant_roid, "roid": roid}
                )

            # Add contacts
            if add_contacts:
                for contact in add_contacts:
                    contact_roid = await self._get_contact_roid(contact["id"], conn)
                    if contact_roid:
                        sql = """
                            MERGE INTO DOMAIN_CONTACTS dc
                            USING (SELECT :domain_roid AS droid, :contact_roid AS croid, :ctype AS ctype FROM DUAL) src
                            ON (dc.DCN_DOMAIN_ROID = src.droid AND dc.DCN_CONTACT_ROID = src.croid AND dc.DCN_TYPE = src.ctype)
                            WHEN NOT MATCHED THEN
                                INSERT (DCN_DOMAIN_ROID, DCN_CONTACT_ROID, DCN_TYPE)
                                VALUES (src.droid, src.croid, src.ctype)
                        """
                        await conn.execute(sql, {
                            "domain_roid": roid,
                            "contact_roid": contact_roid,
                            "ctype": contact["type"]
                        })

            # Remove contacts
            if rem_contacts:
                for contact in rem_contacts:
                    contact_roid = await self._get_contact_roid(contact["id"], conn)
                    if contact_roid:
                        await conn.execute(
                            """DELETE FROM DOMAIN_CONTACTS
                               WHERE DCN_DOMAIN_ROID = :domain_roid
                               AND DCN_CONTACT_ROID = :contact_roid
                               AND DCN_TYPE = :ctype""",
                            {"domain_roid": roid, "contact_roid": contact_roid, "ctype": contact["type"]}
                        )

            # Add nameservers
            if add_nameservers:
                for ns in add_nameservers:
                    host_roid = await self._get_host_roid(ns, conn)
                    if host_roid:
                        sql = """
                            MERGE INTO DOMAIN_NAMESERVERS dn
                            USING (SELECT :domain_roid AS droid, :host_roid AS hroid FROM DUAL) src
                            ON (dn.DNS_DOMAIN_ROID = src.droid AND dn.DNS_HOST_ROID = src.hroid)
                            WHEN NOT MATCHED THEN
                                INSERT (DNS_DOMAIN_ROID, DNS_HOST_ROID)
                                VALUES (src.droid, src.hroid)
                        """
                        await conn.execute(sql, {
                            "domain_roid": roid,
                            "host_roid": host_roid
                        })

            # Remove nameservers
            if rem_nameservers:
                for ns in rem_nameservers:
                    host_roid = await self._get_host_roid(ns, conn)
                    if host_roid:
                        await conn.execute(
                            "DELETE FROM DOMAIN_NAMESERVERS WHERE DNS_DOMAIN_ROID = :domain_roid AND DNS_HOST_ROID = :host_roid",
                            {"domain_roid": roid, "host_roid": host_roid}
                        )

            # Handle statuses
            if add_statuses:
                if any(s != "ok" for s in add_statuses):
                    await conn.execute(
                        "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid AND EDS_STATUS = 'ok'",
                        {"roid": roid}
                    )
                for status in add_statuses:
                    sql = """
                        MERGE INTO EPP_DOMAIN_STATUSES eds
                        USING (SELECT :roid AS roid, :status AS status FROM DUAL) src
                        ON (eds.EDS_ROID = src.roid AND eds.EDS_STATUS = src.status)
                        WHEN NOT MATCHED THEN
                            INSERT (EDS_ROID, EDS_STATUS)
                            VALUES (src.roid, src.status)
                    """
                    await conn.execute(sql, {"roid": roid, "status": status})

            if rem_statuses:
                for status in rem_statuses:
                    await conn.execute(
                        "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid AND EDS_STATUS = :status",
                        {"roid": roid, "status": status}
                    )
                # Add 'ok' if no statuses remain
                result = await conn.query_one(
                    "SELECT COUNT(*) AS cnt FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid",
                    {"roid": roid}
                )
                count = result.get("cnt", 0) if result else 0
                if count == 0:
                    await conn.execute(
                        "INSERT INTO EPP_DOMAIN_STATUSES (EDS_ROID, EDS_STATUS) VALUES (:roid, 'ok')",
                        {"roid": roid}
                    )

        logger.info(f"Updated domain: {domain_name}")
        return await self.get_by_name(domain_name)

    # ========================================================================
    # Delete Operations
    # ========================================================================

    async def delete(self, domain_name: str, immediate: bool = False) -> bool:
        """
        Delete a domain (marks as pendingDelete or immediate deletion).

        Args:
            domain_name: Domain name
            immediate: If True, delete immediately; otherwise mark as pendingDelete

        Returns:
            True if successful

        Raises:
            Exception: If domain not found or delete prohibited
        """
        domain_name = domain_name.lower()

        domain = await self.get_by_name(domain_name)
        if not domain:
            raise Exception(f"Domain {domain_name} not found")

        roid = domain["roid"]

        # Check for delete prohibited status
        statuses = [s["s"] for s in domain["statuses"]]
        if "clientDeleteProhibited" in statuses or "serverDeleteProhibited" in statuses:
            raise Exception("Domain delete prohibited by status")

        async with self.pool.transaction() as conn:
            if immediate:
                # Immediate deletion - remove all records
                await conn.execute(
                    "DELETE FROM DOMAIN_NAMESERVERS WHERE DNS_DOMAIN_ROID = :roid",
                    {"roid": roid}
                )
                await conn.execute(
                    "DELETE FROM DOMAIN_CONTACTS WHERE DCN_DOMAIN_ROID = :roid",
                    {"roid": roid}
                )
                await conn.execute(
                    "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid",
                    {"roid": roid}
                )
                await conn.execute(
                    "DELETE FROM DOMAIN_REGISTRATIONS WHERE DRE_ROID = :roid",
                    {"roid": roid}
                )
                await conn.execute(
                    "DELETE FROM DOMAINS WHERE DOM_ROID = :roid",
                    {"roid": roid}
                )
                await conn.execute(
                    "UPDATE REGISTRY_OBJECTS SET OBJ_STATUS = 'Deleted' WHERE OBJ_ROID = :roid",
                    {"roid": roid}
                )
                logger.info(f"Deleted domain (immediate): {domain_name}")
            else:
                # Mark as pending delete
                await conn.execute(
                    "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid",
                    {"roid": roid}
                )
                await conn.execute(
                    "INSERT INTO EPP_DOMAIN_STATUSES (EDS_ROID, EDS_STATUS) VALUES (:roid, 'pendingDelete')",
                    {"roid": roid}
                )
                await conn.execute(
                    "UPDATE REGISTRY_OBJECTS SET OBJ_STATUS = 'Pending Delete' WHERE OBJ_ROID = :roid",
                    {"roid": roid}
                )
                logger.info(f"Marked domain for deletion: {domain_name}")

        return True

    # ========================================================================
    # Renew Operations
    # ========================================================================

    async def renew(
        self,
        domain_name: str,
        user_id: int,
        current_expiry: datetime,
        period: int = 1,
        unit: str = "y"
    ) -> Dict[str, Any]:
        """
        Renew a domain registration.

        Args:
            domain_name: Domain name
            user_id: Renewing user ID
            current_expiry: Current expiration date (for verification)
            period: Renewal period
            unit: Period unit (y=years, m=months)

        Returns:
            Updated domain data with new expiry

        Raises:
            Exception: If renew fails or expiry doesn't match
        """
        domain_name = domain_name.lower()
        now = datetime.utcnow()

        domain = await self.get_by_name(domain_name)
        if not domain:
            raise Exception(f"Domain {domain_name} not found")

        roid = domain["roid"]
        zone = domain["_zone"]

        # Check for renew prohibited status
        statuses = [s["s"] for s in domain["statuses"]]
        if "clientRenewProhibited" in statuses or "serverRenewProhibited" in statuses:
            raise Exception("Domain renew prohibited by status")

        # Get zone configuration
        zone_config = await self.get_zone(zone)
        if not zone_config:
            raise Exception(f"Zone {zone} not found")

        max_expiry_years = zone_config.get("ZON_MAX_EXPIRY_YEARS", 10)

        # Get current registration
        reg_sql = """
            SELECT DRE_ID, DRE_EXPIRE_DATE
            FROM DOMAIN_REGISTRATIONS
            WHERE DRE_ROID = :roid AND DRE_STATUS = 'approved'
        """
        reg = await self.pool.query_one(reg_sql, {"roid": roid})
        if not reg:
            raise Exception("No active registration found")

        stored_expiry = reg["DRE_EXPIRE_DATE"]

        # Verify current expiry date matches (to ensure client has correct state)
        if isinstance(stored_expiry, datetime):
            stored_date = stored_expiry.date()
        else:
            stored_date = stored_expiry

        if isinstance(current_expiry, datetime):
            provided_date = current_expiry.date()
        else:
            provided_date = current_expiry

        if stored_date != provided_date:
            raise Exception("Current expiration date doesn't match")

        # Calculate new expiry
        if unit == "y":
            new_expiry = stored_expiry + relativedelta(years=period)
        else:
            new_expiry = stored_expiry + relativedelta(months=period)

        # Check max expiry
        max_expiry = now + relativedelta(years=max_expiry_years)
        if new_expiry > max_expiry:
            raise Exception(f"New expiry would exceed maximum of {max_expiry_years} years")

        async with self.pool.transaction() as conn:
            # Update registration
            await conn.execute(
                "UPDATE DOMAIN_REGISTRATIONS SET DRE_EXPIRE_DATE = :new_expiry WHERE DRE_ID = :reg_id",
                {"new_expiry": new_expiry, "reg_id": reg["DRE_ID"]}
            )

            # Update registry object
            await conn.execute(
                "UPDATE REGISTRY_OBJECTS SET OBJ_UPDATE_DATE = :now, OBJ_UPDATE_USER_ID = :user_id WHERE OBJ_ROID = :roid",
                {"now": now, "user_id": user_id, "roid": roid}
            )

        logger.info(f"Renewed domain: {domain_name} until {new_expiry}")

        result = await self.get_by_name(domain_name)
        result["exDate"] = self._format_date(new_expiry)
        return result

    # ========================================================================
    # Transfer Operations
    # ========================================================================

    async def request_transfer(
        self,
        domain_name: str,
        requesting_account_id: int,
        user_id: int,
        auth_info: str,
        period: int = 1,
        unit: str = "y"
    ) -> Dict[str, Any]:
        """
        Request transfer of a domain.

        Args:
            domain_name: Domain name
            requesting_account_id: Account requesting the transfer
            user_id: User ID
            auth_info: Authorization password
            period: Transfer renewal period
            unit: Period unit

        Returns:
            Transfer info dict

        Raises:
            Exception: If transfer cannot be requested
        """
        domain_name = domain_name.lower()
        now = datetime.utcnow()

        domain = await self.get_by_name(domain_name, include_auth=True)
        if not domain:
            raise Exception(f"Domain {domain_name} not found")

        roid = domain["roid"]
        current_account_id = domain["_account_id"]

        # Verify auth info
        if domain["authInfo"] != auth_info:
            raise Exception("Invalid authorization information")

        # Check for transfer prohibited status
        statuses = [s["s"] for s in domain["statuses"]]
        if "clientTransferProhibited" in statuses or "serverTransferProhibited" in statuses:
            raise Exception("Domain transfer prohibited by status")

        # Check if transfer already pending
        existing = await self.get_transfer_info(domain_name)
        if existing:
            raise Exception("Transfer already pending")

        # Get zone for pending days
        zone_config = await self.get_zone(domain["_zone"])
        pending_days = zone_config.get("ZON_TRANSFER_PENDING_DAYS", 5) if zone_config else 5
        accept_date = now + relativedelta(days=pending_days)

        async with self.pool.transaction() as conn:
            # Create transfer record
            trx_id = await conn.get_next_sequence("TRX_ID_SEQ")
            sql = """
                INSERT INTO TRANSFERS (
                    TRX_ID, TRX_ROID, TRX_STATUS,
                    TRX_FROM_ACCOUNT_ID, TRX_TO_ACCOUNT_ID,
                    TRX_REQUEST_DATE, TRX_ACCEPT_DATE,
                    TRX_PERIOD, TRX_UNIT
                ) VALUES (
                    :trx_id, :roid, 'pending',
                    :from_account, :to_account,
                    :request_date, :accept_date,
                    :period, :unit
                )
            """
            await conn.execute(sql, {
                "trx_id": trx_id,
                "roid": roid,
                "from_account": current_account_id,
                "to_account": requesting_account_id,
                "request_date": now,
                "accept_date": accept_date,
                "period": period,
                "unit": unit
            })

            # Add pending transfer status
            await conn.execute(
                "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid AND EDS_STATUS = 'ok'",
                {"roid": roid}
            )
            await conn.execute(
                "INSERT INTO EPP_DOMAIN_STATUSES (EDS_ROID, EDS_STATUS) VALUES (:roid, 'pendingTransfer')",
                {"roid": roid}
            )

        logger.info(f"Transfer requested for domain: {domain_name}")

        return {
            "name": domain_name,
            "trStatus": "pending",
            "reID": str(requesting_account_id),
            "reDate": self._format_date(now),
            "acID": str(current_account_id),
            "acDate": self._format_date(accept_date),
            "exDate": domain.get("exDate")
        }

    async def approve_transfer(self, domain_name: str, user_id: int) -> Dict[str, Any]:
        """
        Approve a pending transfer.

        Args:
            domain_name: Domain name
            user_id: Approving user ID

        Returns:
            Transfer result dict

        Raises:
            Exception: If no pending transfer
        """
        domain_name = domain_name.lower()
        now = datetime.utcnow()

        transfer = await self.get_transfer_info(domain_name)
        if not transfer:
            raise Exception("No pending transfer")

        domain = await self.get_by_name(domain_name)
        roid = domain["roid"]

        async with self.pool.transaction() as conn:
            # Update transfer status
            await conn.execute(
                "UPDATE TRANSFERS SET TRX_STATUS = 'clientApproved', TRX_ACCEPT_DATE = :now WHERE TRX_ID = :trx_id",
                {"now": now, "trx_id": transfer["TRX_ID"]}
            )

            # Update domain owner
            await conn.execute(
                "UPDATE REGISTRY_OBJECTS SET OBJ_MANAGE_ACCOUNT_ID = :new_account, OBJ_TRANSFER_DATE = :now WHERE OBJ_ROID = :roid",
                {"new_account": transfer["TRX_TO_ACCOUNT_ID"], "now": now, "roid": roid}
            )

            # Remove pending transfer status
            await conn.execute(
                "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid AND EDS_STATUS = 'pendingTransfer'",
                {"roid": roid}
            )
            # Add ok if no other statuses
            result = await conn.query_one(
                "SELECT COUNT(*) AS cnt FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid",
                {"roid": roid}
            )
            count = result.get("cnt", 0) if result else 0
            if count == 0:
                await conn.execute(
                    "INSERT INTO EPP_DOMAIN_STATUSES (EDS_ROID, EDS_STATUS) VALUES (:roid, 'ok')",
                    {"roid": roid}
                )

            # Extend expiry if period specified
            if transfer.get("TRX_PERIOD"):
                period = transfer["TRX_PERIOD"]
                unit = transfer.get("TRX_UNIT", "y")
                reg_sql = "SELECT DRE_ID, DRE_EXPIRE_DATE FROM DOMAIN_REGISTRATIONS WHERE DRE_ROID = :roid AND DRE_STATUS = 'approved'"
                reg = await conn.query_one(reg_sql, {"roid": roid})
                if reg:
                    if unit == "y":
                        new_expiry = reg["DRE_EXPIRE_DATE"] + relativedelta(years=period)
                    else:
                        new_expiry = reg["DRE_EXPIRE_DATE"] + relativedelta(months=period)
                    await conn.execute(
                        "UPDATE DOMAIN_REGISTRATIONS SET DRE_EXPIRE_DATE = :new_expiry WHERE DRE_ID = :reg_id",
                        {"new_expiry": new_expiry, "reg_id": reg["DRE_ID"]}
                    )

        logger.info(f"Transfer approved for domain: {domain_name}")
        return {"name": domain_name, "trStatus": "approved"}

    async def reject_transfer(self, domain_name: str, user_id: int) -> Dict[str, Any]:
        """
        Reject a pending transfer.

        Args:
            domain_name: Domain name
            user_id: Rejecting user ID

        Returns:
            Transfer result dict
        """
        domain_name = domain_name.lower()
        now = datetime.utcnow()

        transfer = await self.get_transfer_info(domain_name)
        if not transfer:
            raise Exception("No pending transfer")

        domain = await self.get_by_name(domain_name)
        roid = domain["roid"]

        async with self.pool.transaction() as conn:
            # Update transfer status
            await conn.execute(
                "UPDATE TRANSFERS SET TRX_STATUS = 'clientRejected' WHERE TRX_ID = :trx_id",
                {"trx_id": transfer["TRX_ID"]}
            )

            # Remove pending transfer status
            await conn.execute(
                "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid AND EDS_STATUS = 'pendingTransfer'",
                {"roid": roid}
            )
            result = await conn.query_one(
                "SELECT COUNT(*) AS cnt FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid",
                {"roid": roid}
            )
            count = result.get("cnt", 0) if result else 0
            if count == 0:
                await conn.execute(
                    "INSERT INTO EPP_DOMAIN_STATUSES (EDS_ROID, EDS_STATUS) VALUES (:roid, 'ok')",
                    {"roid": roid}
                )

        logger.info(f"Transfer rejected for domain: {domain_name}")
        return {"name": domain_name, "trStatus": "rejected"}

    async def cancel_transfer(self, domain_name: str, user_id: int) -> Dict[str, Any]:
        """
        Cancel a pending transfer (by requesting registrar).

        Args:
            domain_name: Domain name
            user_id: Cancelling user ID

        Returns:
            Transfer result dict
        """
        domain_name = domain_name.lower()

        transfer = await self.get_transfer_info(domain_name)
        if not transfer:
            raise Exception("No pending transfer")

        domain = await self.get_by_name(domain_name)
        roid = domain["roid"]

        async with self.pool.transaction() as conn:
            await conn.execute(
                "UPDATE TRANSFERS SET TRX_STATUS = 'clientCancelled' WHERE TRX_ID = :trx_id",
                {"trx_id": transfer["TRX_ID"]}
            )
            await conn.execute(
                "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid AND EDS_STATUS = 'pendingTransfer'",
                {"roid": roid}
            )
            result = await conn.query_one(
                "SELECT COUNT(*) AS cnt FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid",
                {"roid": roid}
            )
            count = result.get("cnt", 0) if result else 0
            if count == 0:
                await conn.execute(
                    "INSERT INTO EPP_DOMAIN_STATUSES (EDS_ROID, EDS_STATUS) VALUES (:roid, 'ok')",
                    {"roid": roid}
                )

        logger.info(f"Transfer cancelled for domain: {domain_name}")
        return {"name": domain_name, "trStatus": "cancelled"}

    # ========================================================================
    # Status Management
    # ========================================================================

    async def add_status(
        self,
        domain_name: str,
        status: str,
        lang: Optional[str] = None,
        reason: Optional[str] = None
    ) -> bool:
        """Add a status to domain."""
        domain = await self.get_by_name(domain_name)
        if not domain:
            raise Exception(f"Domain {domain_name} not found")

        roid = domain["roid"]

        if status != "ok":
            await self.pool.execute(
                "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid AND EDS_STATUS = 'ok'",
                {"roid": roid}
            )

        sql = """
            MERGE INTO EPP_DOMAIN_STATUSES eds
            USING (SELECT :roid AS roid, :status AS status FROM DUAL) src
            ON (eds.EDS_ROID = src.roid AND eds.EDS_STATUS = src.status)
            WHEN NOT MATCHED THEN
                INSERT (EDS_ROID, EDS_STATUS, EDS_LANG, EDS_REASON)
                VALUES (src.roid, src.status, :lang, :reason)
        """
        await self.pool.execute(sql, {
            "roid": roid,
            "status": status,
            "lang": lang,
            "reason": reason
        })
        return True

    async def remove_status(self, domain_name: str, status: str) -> bool:
        """Remove a status from domain."""
        domain = await self.get_by_name(domain_name)
        if not domain:
            raise Exception(f"Domain {domain_name} not found")

        roid = domain["roid"]

        await self.pool.execute(
            "DELETE FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid AND EDS_STATUS = :status",
            {"roid": roid, "status": status}
        )

        count = await self.pool.query_value(
            "SELECT COUNT(*) FROM EPP_DOMAIN_STATUSES WHERE EDS_ROID = :roid",
            {"roid": roid}
        )
        if count == 0:
            await self.pool.execute(
                "INSERT INTO EPP_DOMAIN_STATUSES (EDS_ROID, EDS_STATUS) VALUES (:roid, 'ok')",
                {"roid": roid}
            )
        return True

    # ========================================================================
    # ROID Lookup
    # ========================================================================

    async def get_roid(self, domain_name: str) -> Optional[str]:
        """Get ROID for domain."""
        sql = "SELECT DOM_ROID FROM DOMAINS WHERE LOWER(DOM_NAME) = :domain_name"
        return await self.pool.query_value(sql, {"domain_name": domain_name.lower()})

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

    def extract_zone(self, domain_name: str) -> str:
        """Extract zone from domain name."""
        parts = domain_name.lower().split(".")
        if len(parts) >= 2:
            return ".".join(parts[1:])
        return ""

    def extract_label(self, domain_name: str) -> str:
        """Extract label (first part) from domain name."""
        return domain_name.lower().split(".")[0]

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

            # Update domain record
            await conn.execute(
                """UPDATE DOMAINS
                   SET DOM_DELETE_DATE = NULL,
                       DOM_UPDATE_DATE = :update_date,
                       DOM_UPDATE_USER_ID = :user_id
                   WHERE DOM_ROID = :roid""",
                {"roid": domain_roid, "update_date": now, "user_id": user_id}
            )

            # Update registry object
            await conn.execute(
                """UPDATE REGISTRY_OBJECTS
                   SET OBJ_UPDATE_DATE = :update_date,
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
            await conn.execute(
                """UPDATE DOMAINS
                   SET DOM_DELETE_DATE = :delete_date,
                       DOM_UPDATE_DATE = :update_date,
                       DOM_UPDATE_USER_ID = :user_id
                   WHERE DOM_ROID = :roid""",
                {"roid": domain_roid, "delete_date": now, "update_date": now, "user_id": user_id}
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

            # Clear delete date
            await conn.execute(
                """UPDATE DOMAINS
                   SET DOM_DELETE_DATE = NULL,
                       DOM_UPDATE_DATE = :update_date,
                       DOM_UPDATE_USER_ID = :user_id
                   WHERE DOM_ROID = :roid""",
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


# Global repository instance
_domain_repo: Optional[DomainRepository] = None


async def get_domain_repo() -> DomainRepository:
    """Get or create global domain repository."""
    global _domain_repo
    if _domain_repo is None:
        pool = await get_pool()
        _domain_repo = DomainRepository(pool)
    return _domain_repo
