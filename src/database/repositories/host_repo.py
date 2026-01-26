"""
Host Repository

Handles all host/nameserver-related database operations including:
- Availability checks
- Host info retrieval
- Host creation, update, deletion
"""

import logging
from datetime import datetime, date
from typing import Any, Dict, List, Optional, Tuple

from src.database.connection import get_pool, DatabasePool
from src.database.models import HostInfo

logger = logging.getLogger("epp.database.host")


class HostRepository:
    """
    Repository for host operations.

    All queries use parameterized statements to prevent SQL injection.
    """

    def __init__(self, pool: DatabasePool):
        """Initialize with database pool."""
        self.pool = pool

    # ========================================================================
    # Check Operations
    # ========================================================================

    async def check_available(self, hostname: str) -> Tuple[bool, Optional[str]]:
        """
        Check if hostname is available.

        Args:
            hostname: Fully qualified hostname

        Returns:
            Tuple of (is_available, reason_if_not)
        """
        hostname = hostname.lower()

        sql = """
            SELECT h.HOS_ROID, o.OBJ_STATUS
            FROM HOSTS h
            JOIN REGISTRY_OBJECTS o ON h.HOS_ROID = o.OBJ_ROID
            WHERE LOWER(h.HOS_NAME) = :hostname
        """

        row = await self.pool.query_one(sql, {"hostname": hostname})

        if row:
            return False, "In use"

        return True, None

    async def check_multiple(
        self,
        hostnames: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Check availability of multiple hosts.

        Args:
            hostnames: List of hostnames to check

        Returns:
            List of {name, avail, reason} dicts
        """
        results = []
        for name in hostnames:
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

    async def get_by_name(self, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Get host by name with all related data.

        Args:
            hostname: Fully qualified hostname

        Returns:
            Host data dict or None
        """
        hostname = hostname.lower()

        sql = """
            SELECT
                h.HOS_ROID,
                h.HOS_NAME,
                h.HOS_DOMAIN_ROID,
                h.HOS_USERFORM,
                h.HOS_ACTIVE_INDICATOR,
                o.OBJ_STATUS,
                o.OBJ_CREATE_DATE,
                o.OBJ_CREATE_USER_ID,
                o.OBJ_MANAGE_ACCOUNT_ID,
                o.OBJ_UPDATE_DATE,
                o.OBJ_UPDATE_USER_ID,
                cr_user.USR_USERNAME AS CR_USERNAME,
                up_user.USR_USERNAME AS UP_USERNAME,
                acc.ACC_CLIENT_ID AS CL_ID
            FROM HOSTS h
            JOIN REGISTRY_OBJECTS o ON h.HOS_ROID = o.OBJ_ROID
            LEFT JOIN USERS cr_user ON o.OBJ_CREATE_USER_ID = cr_user.USR_ID
            LEFT JOIN USERS up_user ON o.OBJ_UPDATE_USER_ID = up_user.USR_ID
            LEFT JOIN ACCOUNTS acc ON o.OBJ_MANAGE_ACCOUNT_ID = acc.ACC_ID
            WHERE LOWER(h.HOS_NAME) = :hostname
        """

        row = await self.pool.query_one(sql, {"hostname": hostname})

        if not row:
            return None

        roid = row["HOS_ROID"]

        # Get statuses
        statuses = await self._get_host_statuses(roid)

        # Get IP addresses
        addrs = await self._get_host_addresses(roid)

        # Build response
        host_data = {
            "name": row["HOS_NAME"],
            "roid": roid,
            "statuses": statuses,
            "addrs": addrs,
            "clID": row["CL_ID"] or "",
            "crID": row["CR_USERNAME"],
            "crDate": self._format_date(row["OBJ_CREATE_DATE"]),
            "upID": row["UP_USERNAME"],
            "upDate": self._format_date(row["OBJ_UPDATE_DATE"]),
            # Additional fields for internal use
            "_account_id": row["OBJ_MANAGE_ACCOUNT_ID"],
            "_domain_roid": row["HOS_DOMAIN_ROID"],
            "_is_subordinate": row["HOS_DOMAIN_ROID"] is not None,
        }

        return host_data

    async def get_by_roid(self, roid: str) -> Optional[Dict[str, Any]]:
        """
        Get host by ROID.

        Args:
            roid: Registry Object ID

        Returns:
            Host data dict or None
        """
        sql = "SELECT HOS_NAME FROM HOSTS WHERE HOS_ROID = :roid"
        name = await self.pool.query_value(sql, {"roid": roid})

        if not name:
            return None

        return await self.get_by_name(name)

    async def _get_host_statuses(self, roid: str) -> List[Dict[str, Any]]:
        """Get EPP statuses for host."""
        sql = """
            SELECT EHS_STATUS, EHS_LANG, EHS_REASON
            FROM EPP_HOST_STATUSES
            WHERE EHS_ROID = :roid
        """
        rows = await self.pool.query(sql, {"roid": roid})

        statuses = []
        for row in rows:
            statuses.append({
                "s": row["EHS_STATUS"],
                "lang": row.get("EHS_LANG"),
                "reason": row.get("EHS_REASON")
            })

        # Add default status if none
        if not statuses:
            statuses.append({"s": "ok"})

        return statuses

    async def _get_host_addresses(self, roid: str) -> List[Dict[str, Any]]:
        """Get IP addresses for host."""
        sql = """
            SELECT HAD_ADDRESS, HAD_TYPE
            FROM HOST_ADDRESSES
            WHERE HAD_ROID = :roid
            ORDER BY HAD_TYPE, HAD_ADDRESS
        """
        rows = await self.pool.query(sql, {"roid": roid})

        addrs = []
        for row in rows:
            addrs.append({
                "addr": row["HAD_ADDRESS"],
                "ip": row["HAD_TYPE"]  # v4 or v6
            })

        return addrs

    # ========================================================================
    # Authorization Operations
    # ========================================================================

    async def get_sponsoring_account(self, hostname: str) -> Optional[int]:
        """
        Get account ID that sponsors the host.

        Args:
            hostname: Host name

        Returns:
            Account ID or None
        """
        sql = """
            SELECT o.OBJ_MANAGE_ACCOUNT_ID
            FROM HOSTS h
            JOIN REGISTRY_OBJECTS o ON h.HOS_ROID = o.OBJ_ROID
            WHERE LOWER(h.HOS_NAME) = :hostname
        """
        result = await self.pool.query_value(sql, {"hostname": hostname.lower()})
        return int(result) if result else None

    # ========================================================================
    # Subordinate Host Operations
    # ========================================================================

    async def is_subordinate(self, hostname: str) -> bool:
        """
        Check if host is a subordinate (glue) host.

        A subordinate host is one whose name is within a domain
        managed by the same registry.

        Args:
            hostname: Host name

        Returns:
            True if subordinate host
        """
        sql = """
            SELECT HOS_DOMAIN_ROID
            FROM HOSTS
            WHERE LOWER(HOS_NAME) = :hostname
        """
        domain_roid = await self.pool.query_value(sql, {"hostname": hostname.lower()})
        return domain_roid is not None

    async def get_parent_domain(self, hostname: str) -> Optional[str]:
        """
        Get parent domain for subordinate host.

        Args:
            hostname: Host name

        Returns:
            Parent domain name or None
        """
        sql = """
            SELECT d.DOM_NAME
            FROM HOSTS h
            JOIN DOMAINS d ON h.HOS_DOMAIN_ROID = d.DOM_ROID
            WHERE LOWER(h.HOS_NAME) = :hostname
        """
        return await self.pool.query_value(sql, {"hostname": hostname.lower()})

    async def requires_glue(self, hostname: str, domain_name: str) -> bool:
        """
        Check if host requires glue records for a domain.

        A host requires glue if it's subordinate to the domain.

        Args:
            hostname: Host name
            domain_name: Domain name

        Returns:
            True if glue required
        """
        hostname = hostname.lower()
        domain_name = domain_name.lower()

        # Host requires glue if it ends with the domain name
        return hostname.endswith("." + domain_name) or hostname == domain_name

    # ========================================================================
    # Usage Check Operations
    # ========================================================================

    async def is_in_use(self, hostname: str) -> Tuple[bool, Optional[str]]:
        """
        Check if host is in use as nameserver for any domains.

        Args:
            hostname: Host name

        Returns:
            Tuple of (is_in_use, usage_description)
        """
        # Get ROID first
        sql = "SELECT HOS_ROID FROM HOSTS WHERE LOWER(HOS_NAME) = :hostname"
        roid = await self.pool.query_value(sql, {"hostname": hostname.lower()})

        if not roid:
            return False, None

        # Check if used as nameserver
        sql = """
            SELECT COUNT(*) FROM DOMAIN_NAMESERVERS
            WHERE DNS_HOST_ROID = :roid
        """
        count = await self.pool.query_value(sql, {"roid": roid})
        if count and int(count) > 0:
            return True, f"Used as nameserver for {count} domain(s)"

        return False, None

    async def get_linked_domains(self, hostname: str) -> List[str]:
        """
        Get list of domains using this host as nameserver.

        Args:
            hostname: Host name

        Returns:
            List of domain names
        """
        sql = "SELECT HOS_ROID FROM HOSTS WHERE LOWER(HOS_NAME) = :hostname"
        roid = await self.pool.query_value(sql, {"hostname": hostname.lower()})

        if not roid:
            return []

        sql = """
            SELECT d.DOM_NAME
            FROM DOMAIN_NAMESERVERS dn
            JOIN DOMAINS d ON dn.DNS_DOMAIN_ROID = d.DOM_ROID
            WHERE dn.DNS_HOST_ROID = :roid
        """
        rows = await self.pool.query(sql, {"roid": roid})
        return [row["DOM_NAME"] for row in rows]

    # ========================================================================
    # ROID Lookup
    # ========================================================================

    async def get_roid(self, hostname: str) -> Optional[str]:
        """
        Get ROID for hostname.

        Args:
            hostname: Host name

        Returns:
            ROID or None
        """
        sql = "SELECT HOS_ROID FROM HOSTS WHERE LOWER(HOS_NAME) = :hostname"
        return await self.pool.query_value(sql, {"hostname": hostname.lower()})

    # ========================================================================
    # Validation Operations
    # ========================================================================

    async def validate_addresses_for_subordinate(
        self,
        hostname: str,
        addresses: List[Dict[str, str]]
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate that subordinate host has required addresses.

        Subordinate hosts must have at least one IP address (glue).

        Args:
            hostname: Host name
            addresses: List of {addr, ip} dicts

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if this will be a subordinate host
        # Extract potential parent domain from hostname
        parts = hostname.lower().split(".")
        if len(parts) < 3:
            # Not subordinate, no addresses required
            return True, None

        # Check if parent domain exists in our registry
        for i in range(1, len(parts) - 1):
            potential_domain = ".".join(parts[i:])
            sql = """
                SELECT COUNT(*) FROM DOMAINS
                WHERE LOWER(DOM_NAME) = :domain_name
            """
            count = await self.pool.query_value(sql, {"domain_name": potential_domain})
            if count and int(count) > 0:
                # This is a subordinate host - must have addresses
                if not addresses:
                    return False, f"Subordinate host {hostname} requires at least one IP address"
                return True, None

        # Not subordinate
        return True, None

    # ========================================================================
    # Create Operations
    # ========================================================================

    async def create(
        self,
        hostname: str,
        roid: str,
        account_id: int,
        user_id: int,
        addresses: Optional[List[Dict[str, str]]] = None,
        parent_domain_roid: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new host.

        Args:
            hostname: Fully qualified hostname
            roid: Pre-generated ROID
            account_id: Sponsoring account ID
            user_id: Creating user ID
            addresses: Optional list of {addr, ip} dicts (ip = 'v4' or 'v6')
            parent_domain_roid: Optional parent domain ROID for subordinate hosts

        Returns:
            Created host data dict

        Raises:
            Exception: If host already exists or creation fails
        """
        hostname = hostname.lower()
        now = datetime.utcnow()

        # Check if host already exists
        existing = await self.check_available(hostname)
        if not existing[0]:
            raise Exception(f"Host {hostname} already exists")

        # Validate subordinate host has addresses
        if parent_domain_roid and not addresses:
            raise Exception("Subordinate host requires at least one IP address")

        async with self.pool.transaction() as conn:
            # Insert into REGISTRY_OBJECTS first
            obj_sql = """
                INSERT INTO REGISTRY_OBJECTS (
                    OBJ_ROID, OBJ_TYPE, OBJ_STATUS,
                    OBJ_CREATE_DATE, OBJ_CREATE_USER_ID,
                    OBJ_MANAGE_ACCOUNT_ID, OBJ_LOCKED
                ) VALUES (
                    :roid, 'Host', 'Registered',
                    :create_date, :user_id,
                    :account_id, 'N'
                )
            """
            await conn.execute(obj_sql, {
                "roid": roid,
                "create_date": now,
                "user_id": user_id,
                "account_id": account_id
            })

            # Insert into HOSTS
            host_sql = """
                INSERT INTO HOSTS (
                    HOS_ROID, HOS_NAME, HOS_DOMAIN_ROID,
                    HOS_USERFORM, HOS_ACTIVE_INDICATOR
                ) VALUES (
                    :roid, :hostname, :domain_roid,
                    :userform, 'Y'
                )
            """
            await conn.execute(host_sql, {
                "roid": roid,
                "hostname": hostname,
                "domain_roid": parent_domain_roid,
                "userform": hostname
            })

            # Insert IP addresses if provided
            if addresses:
                for addr in addresses:
                    addr_sql = """
                        INSERT INTO HOST_ADDRESSES (
                            HAD_ROID, HAD_ADDRESS, HAD_TYPE
                        ) VALUES (
                            :roid, :address, :addr_type
                        )
                    """
                    await conn.execute(addr_sql, {
                        "roid": roid,
                        "address": addr["addr"],
                        "addr_type": addr.get("ip", "v4")
                    })

            # Add default 'ok' status
            status_sql = """
                INSERT INTO EPP_HOST_STATUSES (
                    EHS_ROID, EHS_STATUS
                ) VALUES (
                    :roid, 'ok'
                )
            """
            await conn.execute(status_sql, {"roid": roid})

        logger.info(f"Created host: {hostname} (ROID: {roid})")

        return await self.get_by_name(hostname)

    async def find_parent_domain_roid(self, hostname: str) -> Optional[str]:
        """
        Find parent domain ROID for a potential subordinate host.

        Args:
            hostname: Host name to check

        Returns:
            Parent domain ROID or None if not subordinate
        """
        parts = hostname.lower().split(".")
        if len(parts) < 3:
            return None

        # Check each potential parent domain
        for i in range(1, len(parts) - 1):
            potential_domain = ".".join(parts[i:])
            sql = """
                SELECT DOM_ROID FROM DOMAINS
                WHERE LOWER(DOM_NAME) = :domain_name
            """
            roid = await self.pool.query_value(sql, {"domain_name": potential_domain})
            if roid:
                return roid

        return None

    # ========================================================================
    # Update Operations
    # ========================================================================

    async def update(
        self,
        hostname: str,
        user_id: int,
        add_addresses: Optional[List[Dict[str, str]]] = None,
        rem_addresses: Optional[List[Dict[str, str]]] = None,
        add_statuses: Optional[List[str]] = None,
        rem_statuses: Optional[List[str]] = None,
        new_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update an existing host.

        Args:
            hostname: Current hostname
            user_id: Updating user ID
            add_addresses: Addresses to add [{addr, ip}]
            rem_addresses: Addresses to remove [{addr, ip}]
            add_statuses: Statuses to add
            rem_statuses: Statuses to remove
            new_name: New hostname (for rename)

        Returns:
            Updated host data dict

        Raises:
            Exception: If host not found or update fails
        """
        hostname = hostname.lower()
        now = datetime.utcnow()

        # Get current host data
        host = await self.get_by_name(hostname)
        if not host:
            raise Exception(f"Host {hostname} not found")

        roid = host["roid"]

        # Check for update prohibited status
        statuses = [s["s"] for s in host["statuses"]]
        if "clientUpdateProhibited" in statuses or "serverUpdateProhibited" in statuses:
            raise Exception("Host update prohibited by status")

        async with self.pool.transaction() as conn:
            # Update REGISTRY_OBJECTS
            obj_sql = """
                UPDATE REGISTRY_OBJECTS
                SET OBJ_UPDATE_DATE = :update_date,
                    OBJ_UPDATE_USER_ID = :user_id
                WHERE OBJ_ROID = :roid
            """
            await conn.execute(obj_sql, {
                "update_date": now,
                "user_id": user_id,
                "roid": roid
            })

            # Add addresses
            if add_addresses:
                for addr in add_addresses:
                    addr_sql = """
                        INSERT INTO HOST_ADDRESSES (
                            HAD_ROID, HAD_ADDRESS, HAD_TYPE
                        ) VALUES (
                            :roid, :address, :addr_type
                        )
                    """
                    await conn.execute(addr_sql, {
                        "roid": roid,
                        "address": addr["addr"],
                        "addr_type": addr.get("ip", "v4")
                    })

            # Remove addresses
            if rem_addresses:
                for addr in rem_addresses:
                    addr_sql = """
                        DELETE FROM HOST_ADDRESSES
                        WHERE HAD_ROID = :roid
                        AND HAD_ADDRESS = :address
                        AND HAD_TYPE = :addr_type
                    """
                    await conn.execute(addr_sql, {
                        "roid": roid,
                        "address": addr["addr"],
                        "addr_type": addr.get("ip", "v4")
                    })

            # Handle statuses
            if add_statuses:
                # Remove 'ok' if adding other statuses
                if any(s != "ok" for s in add_statuses):
                    await conn.execute(
                        "DELETE FROM EPP_HOST_STATUSES WHERE EHS_ROID = :roid AND EHS_STATUS = 'ok'",
                        {"roid": roid}
                    )

                for status in add_statuses:
                    status_sql = """
                        MERGE INTO EPP_HOST_STATUSES ehs
                        USING (SELECT :roid AS roid, :status AS status FROM DUAL) src
                        ON (ehs.EHS_ROID = src.roid AND ehs.EHS_STATUS = src.status)
                        WHEN NOT MATCHED THEN
                            INSERT (EHS_ROID, EHS_STATUS)
                            VALUES (src.roid, src.status)
                    """
                    await conn.execute(status_sql, {
                        "roid": roid,
                        "status": status
                    })

            if rem_statuses:
                for status in rem_statuses:
                    await conn.execute(
                        "DELETE FROM EPP_HOST_STATUSES WHERE EHS_ROID = :roid AND EHS_STATUS = :status",
                        {"roid": roid, "status": status}
                    )

                # Add 'ok' if no statuses remain
                result = await conn.query_one(
                    "SELECT COUNT(*) AS cnt FROM EPP_HOST_STATUSES WHERE EHS_ROID = :roid",
                    {"roid": roid}
                )
                count = result.get("cnt", 0) if result else 0
                if count == 0:
                    await conn.execute(
                        "INSERT INTO EPP_HOST_STATUSES (EHS_ROID, EHS_STATUS) VALUES (:roid, 'ok')",
                        {"roid": roid}
                    )

            # Handle rename
            if new_name:
                new_name = new_name.lower()

                # Check if new name is available
                avail, _ = await self.check_available(new_name)
                if not avail:
                    raise Exception(f"Host {new_name} already exists")

                # Check if new name would be subordinate
                new_parent_roid = await self.find_parent_domain_roid(new_name)

                # Update host name
                rename_sql = """
                    UPDATE HOSTS
                    SET HOS_NAME = :new_name,
                        HOS_USERFORM = :userform,
                        HOS_DOMAIN_ROID = :domain_roid
                    WHERE HOS_ROID = :roid
                """
                await conn.execute(rename_sql, {
                    "new_name": new_name,
                    "userform": new_name,
                    "domain_roid": new_parent_roid,
                    "roid": roid
                })

                hostname = new_name

        # Validate subordinate host still has addresses if applicable
        updated_host = await self.get_by_name(hostname)
        if updated_host["_is_subordinate"] and not updated_host["addrs"]:
            logger.warning(f"Subordinate host {hostname} has no IP addresses")

        logger.info(f"Updated host: {hostname}")
        return updated_host

    # ========================================================================
    # Delete Operations
    # ========================================================================

    async def delete(self, hostname: str) -> bool:
        """
        Delete a host.

        Args:
            hostname: Hostname to delete

        Returns:
            True if deleted successfully

        Raises:
            Exception: If host not found, in use, or delete prohibited
        """
        hostname = hostname.lower()

        # Get current host data
        host = await self.get_by_name(hostname)
        if not host:
            raise Exception(f"Host {hostname} not found")

        roid = host["roid"]

        # Check for delete prohibited status
        statuses = [s["s"] for s in host["statuses"]]
        if "clientDeleteProhibited" in statuses or "serverDeleteProhibited" in statuses:
            raise Exception("Host delete prohibited by status")

        # Check if host is in use
        in_use, reason = await self.is_in_use(hostname)
        if in_use:
            raise Exception(f"Cannot delete host: {reason}")

        async with self.pool.transaction() as conn:
            # Delete IP addresses
            await conn.execute(
                "DELETE FROM HOST_ADDRESSES WHERE HAD_ROID = :roid",
                {"roid": roid}
            )

            # Delete statuses
            await conn.execute(
                "DELETE FROM EPP_HOST_STATUSES WHERE EHS_ROID = :roid",
                {"roid": roid}
            )

            # Delete from HOSTS
            await conn.execute(
                "DELETE FROM HOSTS WHERE HOS_ROID = :roid",
                {"roid": roid}
            )

            # Update REGISTRY_OBJECTS status (or delete)
            await conn.execute(
                "UPDATE REGISTRY_OBJECTS SET OBJ_STATUS = 'Deleted' WHERE OBJ_ROID = :roid",
                {"roid": roid}
            )

        logger.info(f"Deleted host: {hostname}")
        return True

    # ========================================================================
    # Status Management
    # ========================================================================

    async def add_status(
        self,
        hostname: str,
        status: str,
        lang: Optional[str] = None,
        reason: Optional[str] = None
    ) -> bool:
        """
        Add a status to a host.

        Args:
            hostname: Hostname
            status: Status to add
            lang: Optional language code
            reason: Optional reason text

        Returns:
            True if status added
        """
        roid = await self.get_roid(hostname)
        if not roid:
            raise Exception(f"Host {hostname} not found")

        # Remove 'ok' status if adding other status
        if status != "ok":
            await self.pool.execute(
                "DELETE FROM EPP_HOST_STATUSES WHERE EHS_ROID = :roid AND EHS_STATUS = 'ok'",
                {"roid": roid}
            )

        sql = """
            MERGE INTO EPP_HOST_STATUSES ehs
            USING (SELECT :roid AS roid, :status AS status FROM DUAL) src
            ON (ehs.EHS_ROID = src.roid AND ehs.EHS_STATUS = src.status)
            WHEN NOT MATCHED THEN
                INSERT (EHS_ROID, EHS_STATUS, EHS_LANG, EHS_REASON)
                VALUES (src.roid, src.status, :lang, :reason)
        """
        await self.pool.execute(sql, {
            "roid": roid,
            "status": status,
            "lang": lang,
            "reason": reason
        })

        logger.debug(f"Added status {status} to host {hostname}")
        return True

    async def remove_status(self, hostname: str, status: str) -> bool:
        """
        Remove a status from a host.

        Args:
            hostname: Hostname
            status: Status to remove

        Returns:
            True if status removed
        """
        roid = await self.get_roid(hostname)
        if not roid:
            raise Exception(f"Host {hostname} not found")

        await self.pool.execute(
            "DELETE FROM EPP_HOST_STATUSES WHERE EHS_ROID = :roid AND EHS_STATUS = :status",
            {"roid": roid, "status": status}
        )

        # Add 'ok' if no statuses remain
        count = await self.pool.query_value(
            "SELECT COUNT(*) FROM EPP_HOST_STATUSES WHERE EHS_ROID = :roid",
            {"roid": roid}
        )
        if count == 0:
            await self.pool.execute(
                "INSERT INTO EPP_HOST_STATUSES (EHS_ROID, EHS_STATUS) VALUES (:roid, 'ok')",
                {"roid": roid}
            )

        logger.debug(f"Removed status {status} from host {hostname}")
        return True

    async def set_linked_status(self, hostname: str) -> bool:
        """
        Set 'linked' status when host is used as nameserver.

        Args:
            hostname: Hostname

        Returns:
            True if status set
        """
        return await self.add_status(hostname, "linked")

    async def remove_linked_status_if_unused(self, hostname: str) -> bool:
        """
        Remove 'linked' status if host is no longer used.

        Args:
            hostname: Hostname

        Returns:
            True if status was removed or host still in use
        """
        in_use, _ = await self.is_in_use(hostname)
        if not in_use:
            await self.remove_status(hostname, "linked")
            return True
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
_host_repo: Optional[HostRepository] = None


async def get_host_repo() -> HostRepository:
    """Get or create global host repository."""
    global _host_repo
    if _host_repo is None:
        pool = await get_pool()
        _host_repo = HostRepository(pool)
    return _host_repo
