"""
Account Repository

Handles operations on ACCOUNTS, USERS, and ACCOUNT_EPP_ADDRESSES tables.
Used for authentication, authorization, and billing.
"""

import logging
import hashlib
import secrets
import hmac
from datetime import datetime, date
from typing import Any, Dict, List, Optional
from decimal import Decimal

from src.database.connection import get_pool, DatabasePool
from src.database.models import Account, User, AccountEPPAddress

logger = logging.getLogger("epp.database.account")


class AccountRepository:
    """
    Repository for account and user operations.

    Handles:
    - Account lookup by client ID
    - User authentication
    - IP whitelist verification
    - Balance management
    """

    def __init__(self, pool: DatabasePool):
        """Initialize with database pool."""
        self.pool = pool

    # ========================================================================
    # Account Operations
    # ========================================================================

    async def get_account_by_id(self, account_id: int) -> Optional[Dict[str, Any]]:
        """
        Get account by ID.

        Args:
            account_id: Account ID

        Returns:
            Account data or None
        """
        sql = """
            SELECT ACC_ID, ACC_CLIENT_ID, ACC_NAME, ACC_STATUS,
                   ACC_BALANCE, ACC_CREDIT_LIMIT, ACC_CREDIT_LIMIT_ENABLED,
                   ACC_EPP_MAX_CONNECTIONS, ACC_URL,
                   ACC_STREET1, ACC_CITY, ACC_STATE, ACC_COUNTRY,
                   ACC_CREATE_DATE
            FROM ACCOUNTS
            WHERE ACC_ID = :account_id
        """
        return await self.pool.query_one(sql, {"account_id": account_id})

    async def get_account_by_client_id(self, client_id: str) -> Optional[Dict[str, Any]]:
        """
        Get account by EPP client ID.

        Args:
            client_id: EPP client ID (clID)

        Returns:
            Account data or None
        """
        sql = """
            SELECT ACC_ID, ACC_CLIENT_ID, ACC_NAME, ACC_STATUS,
                   ACC_BALANCE, ACC_CREDIT_LIMIT, ACC_CREDIT_LIMIT_ENABLED,
                   ACC_EPP_MAX_CONNECTIONS, ACC_URL,
                   ACC_STREET1, ACC_CITY, ACC_STATE, ACC_COUNTRY,
                   ACC_CREATE_DATE
            FROM ACCOUNTS
            WHERE ACC_CLIENT_ID = :client_id
        """
        return await self.pool.query_one(sql, {"client_id": client_id})

    async def get_account_status(self, account_id: int) -> Optional[str]:
        """
        Get account status.

        Args:
            account_id: Account ID

        Returns:
            Status string or None
        """
        sql = "SELECT ACC_STATUS FROM ACCOUNTS WHERE ACC_ID = :account_id"
        return await self.pool.query_value(sql, {"account_id": account_id})

    async def is_account_active(self, account_id: int) -> bool:
        """
        Check if account is active.

        Args:
            account_id: Account ID

        Returns:
            True if account is active
        """
        status = await self.get_account_status(account_id)
        return status == "Active"

    # ========================================================================
    # User Operations
    # ========================================================================

    async def get_user_by_username(
        self,
        username: str,
        account_id: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get user by username.

        Args:
            username: EPP username
            account_id: Optional account ID filter

        Returns:
            User data or None
        """
        sql = """
            SELECT USR_ID, USR_USERNAME, USR_PASSWORD, USR_TYPE,
                   USR_ACCOUNT_ID, USR_STATUS, USR_FAILED_LOGIN_ATTEMPTS,
                   USR_LAST_LOGON_DATE
            FROM USERS
            WHERE UPPER(USR_USERNAME) = UPPER(:username)
              AND USR_TYPE = 'EPP'
        """
        params = {"username": username}

        if account_id is not None:
            sql += " AND USR_ACCOUNT_ID = :account_id"
            params["account_id"] = account_id

        return await self.pool.query_one(sql, params)

    async def get_epp_user_by_client_id(
        self,
        client_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get EPP user by account's client ID (ACC_CLIENT_ID).

        This is the correct lookup for EPP login - the clID in EPP maps to
        ACC_CLIENT_ID in the ACCOUNTS table, not USR_USERNAME in USERS.

        Args:
            client_id: EPP client ID (clID) which matches ACC_CLIENT_ID

        Returns:
            User data with account info, or None
        """
        sql = """
            SELECT u.USR_ID, u.USR_USERNAME, u.USR_PASSWORD, u.USR_TYPE,
                   u.USR_ACCOUNT_ID, u.USR_STATUS, u.USR_FAILED_LOGIN_ATTEMPTS,
                   u.USR_LAST_LOGON_DATE,
                   a.ACC_ID, a.ACC_CLIENT_ID, a.ACC_NAME, a.ACC_STATUS AS ACC_STATUS
            FROM USERS u
            JOIN ACCOUNTS a ON u.USR_ACCOUNT_ID = a.ACC_ID
            WHERE a.ACC_CLIENT_ID = :client_id
              AND u.USR_TYPE = 'EPP'
        """
        return await self.pool.query_one(sql, {"client_id": client_id})

    async def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get user by ID.

        Args:
            user_id: User ID

        Returns:
            User data or None
        """
        sql = """
            SELECT USR_ID, USR_USERNAME, USR_PASSWORD, USR_TYPE,
                   USR_ACCOUNT_ID, USR_STATUS, USR_FAILED_LOGIN_ATTEMPTS,
                   USR_LAST_LOGON_DATE
            FROM USERS
            WHERE USR_ID = :user_id
        """
        return await self.pool.query_one(sql, {"user_id": user_id})

    async def validate_credentials(
        self,
        client_id: str,
        password: str
    ) -> Optional[Dict[str, Any]]:
        """
        Validate EPP user credentials.

        Tries to find user by:
        1. USR_USERNAME (case-insensitive) - most common case
        2. ACC_CLIENT_ID in ACCOUNTS table - fallback

        Args:
            client_id: EPP client ID (clID) - usually the username
            password: Plain text password

        Returns:
            User data if valid, None otherwise
        """
        # First try: direct username lookup (case-insensitive)
        user = await self.get_user_by_username(client_id)
        if not user:
            # Fallback: try lookup by account's client ID
            user = await self.get_epp_user_by_client_id(client_id)
            if not user:
                logger.warning(f"No EPP user found for client_id: {client_id}")
                return None

        # Check user status
        if user["USR_STATUS"] != "Active":
            logger.warning(f"User not active: {user['USR_USERNAME']} (status={user['USR_STATUS']})")
            return None

        # Check account status (from joined query or separate lookup)
        acc_status = user.get("ACC_STATUS")
        if not acc_status:
            account = await self.get_account_by_id(user["USR_ACCOUNT_ID"])
            if not account:
                logger.warning(f"Account not found for user: {user['USR_USERNAME']}")
                return None
            acc_status = account["ACC_STATUS"]
            user["account"] = account
        else:
            # Build account dict from joined query results
            user["account"] = {
                "ACC_ID": user.get("ACC_ID"),
                "ACC_CLIENT_ID": user.get("ACC_CLIENT_ID"),
                "ACC_NAME": user.get("ACC_NAME"),
                "ACC_STATUS": acc_status,
            }

        if acc_status != "Active":
            logger.warning(f"Account not active for user: {user['USR_USERNAME']}")
            return None

        # Verify password - ARI uses MD5(username + '/' + password)
        username = user["USR_USERNAME"]
        stored_hash = user["USR_PASSWORD"]
        computed_hash = self._hash_password(username, password)
        logger.debug(f"Auth check - User: {username}, Client ID: {client_id}")
        logger.debug(f"Stored hash: {stored_hash}, Computed hash: {computed_hash}")

        if not self._verify_password(username, password, stored_hash):
            logger.warning(f"Invalid password for user: {username} (client_id: {client_id})")
            await self.increment_failed_logins(user["USR_ID"])
            return None

        # Success - reset failed logins and update last logon
        await self.reset_failed_logins(user["USR_ID"])
        await self.update_last_logon(user["USR_ID"])

        return user

    async def increment_failed_logins(self, user_id: int) -> int:
        """
        Increment failed login count.

        Args:
            user_id: User ID

        Returns:
            New failure count
        """
        await self.pool.execute(
            """UPDATE USERS
               SET USR_FAILED_LOGIN_ATTEMPTS = USR_FAILED_LOGIN_ATTEMPTS + 1
               WHERE USR_ID = :user_id""",
            {"user_id": user_id}
        )

        result = await self.pool.query_value(
            "SELECT USR_FAILED_LOGIN_ATTEMPTS FROM USERS WHERE USR_ID = :user_id",
            {"user_id": user_id}
        )
        return int(result) if result else 0

    async def reset_failed_logins(self, user_id: int) -> None:
        """Reset failed login count to zero."""
        await self.pool.execute(
            "UPDATE USERS SET USR_FAILED_LOGIN_ATTEMPTS = 0 WHERE USR_ID = :user_id",
            {"user_id": user_id}
        )

    async def update_last_logon(self, user_id: int) -> None:
        """Update user's last logon date."""
        await self.pool.execute(
            "UPDATE USERS SET USR_LAST_LOGON_DATE = :logon_date WHERE USR_ID = :user_id",
            {"user_id": user_id, "logon_date": datetime.utcnow()}
        )

    async def change_password(
        self,
        user_id: int,
        username: str,
        new_password: str
    ) -> None:
        """
        Change user password.

        Args:
            user_id: User ID
            username: Username (needed for hash)
            new_password: New plain text password
        """
        hashed = self._hash_password(username, new_password)
        await self.pool.execute(
            "UPDATE USERS SET USR_PASSWORD = :password WHERE USR_ID = :user_id",
            {"user_id": user_id, "password": hashed}
        )
        logger.info(f"Password changed for user {user_id}")

    # ========================================================================
    # IP Whitelist Operations
    # ========================================================================

    async def check_ip_whitelist(
        self,
        account_id: int,
        ip_address: str
    ) -> bool:
        """
        Check if IP address is whitelisted for account.

        Handles both IPv4 and IPv6-mapped IPv4 formats (::ffff:x.x.x.x)
        since the portal stores IPs in IPv6-mapped format.

        Args:
            account_id: Account ID
            ip_address: Client IP address to check

        Returns:
            True if IP is allowed
        """
        # Build list of IP formats to check
        # Portal stores as ::ffff:x.x.x.x (IPv6-mapped IPv4)
        ip_variants = [ip_address]

        # If it's a plain IPv4, also check IPv6-mapped format
        if '.' in ip_address and ':' not in ip_address:
            ip_variants.append(f"::ffff:{ip_address}")
        # If it's IPv6-mapped, also check plain IPv4
        elif ip_address.startswith("::ffff:"):
            ip_variants.append(ip_address.replace("::ffff:", ""))

        sql = """
            SELECT COUNT(*) FROM ACCOUNT_EPP_ADDRESSES
            WHERE AEA_ACC_ID = :account_id
              AND AEA_IP_ADDRESS IN (:ip1, :ip2)
              AND AEA_ACTIVE_DATE <= :today
        """

        today = date.today()
        logger.debug(f"Checking IP whitelist: account={account_id}, ip={ip_address}, variants={ip_variants}")

        count = await self.pool.query_value(sql, {
            "account_id": account_id,
            "ip1": ip_variants[0],
            "ip2": ip_variants[1] if len(ip_variants) > 1 else ip_variants[0],
            "today": today
        })

        allowed = int(count) > 0 if count else False

        if not allowed:
            logger.warning(
                f"IP {ip_address} not whitelisted for account {account_id}"
            )

        return allowed

    async def get_whitelisted_ips(self, account_id: int) -> List[str]:
        """
        Get all whitelisted IPs for account.

        Args:
            account_id: Account ID

        Returns:
            List of IP addresses
        """
        sql = """
            SELECT AEA_IP_ADDRESS FROM ACCOUNT_EPP_ADDRESSES
            WHERE AEA_ACC_ID = :account_id
              AND AEA_ACTIVE_DATE <= :today
            ORDER BY AEA_IP_ADDRESS
        """

        rows = await self.pool.query(sql, {
            "account_id": account_id,
            "today": date.today()
        })

        return [row["AEA_IP_ADDRESS"] for row in rows]

    # ========================================================================
    # Balance Operations
    # ========================================================================

    async def get_balance(self, account_id: int) -> Decimal:
        """
        Get account balance.

        Args:
            account_id: Account ID

        Returns:
            Current balance
        """
        sql = "SELECT ACC_BALANCE FROM ACCOUNTS WHERE ACC_ID = :account_id"
        result = await self.pool.query_value(sql, {"account_id": account_id})
        return Decimal(str(result)) if result else Decimal("0")

    async def get_credit_limit(self, account_id: int) -> Decimal:
        """
        Get account credit limit.

        Args:
            account_id: Account ID

        Returns:
            Credit limit (0 if not enabled)
        """
        sql = """
            SELECT ACC_CREDIT_LIMIT, ACC_CREDIT_LIMIT_ENABLED
            FROM ACCOUNTS WHERE ACC_ID = :account_id
        """
        row = await self.pool.query_one(sql, {"account_id": account_id})

        if not row or row["ACC_CREDIT_LIMIT_ENABLED"] != "Y":
            return Decimal("0")

        return Decimal(str(row["ACC_CREDIT_LIMIT"]))

    async def get_available_balance(self, account_id: int) -> Decimal:
        """
        Get available balance (balance + credit limit).

        Args:
            account_id: Account ID

        Returns:
            Available balance
        """
        balance = await self.get_balance(account_id)
        credit = await self.get_credit_limit(account_id)
        return balance + credit

    async def can_afford(self, account_id: int, amount: Decimal) -> bool:
        """
        Check if account can afford a transaction.

        Args:
            account_id: Account ID
            amount: Transaction amount

        Returns:
            True if account has sufficient funds
        """
        available = await self.get_available_balance(account_id)
        return available >= amount

    async def debit_balance(
        self,
        account_id: int,
        amount: Decimal
    ) -> Decimal:
        """
        Debit account balance.

        Args:
            account_id: Account ID
            amount: Amount to debit

        Returns:
            New balance

        Raises:
            ValueError: If insufficient funds
        """
        # Check if can afford
        if not await self.can_afford(account_id, amount):
            raise ValueError(f"Insufficient funds for account {account_id}")

        # Debit
        sql = """
            UPDATE ACCOUNTS
            SET ACC_BALANCE = ACC_BALANCE - :amount
            WHERE ACC_ID = :account_id
        """
        await self.pool.execute(sql, {
            "account_id": account_id,
            "amount": amount
        })

        new_balance = await self.get_balance(account_id)
        logger.info(
            f"Debited {amount} from account {account_id}, "
            f"new balance: {new_balance}"
        )

        return new_balance

    async def credit_balance(
        self,
        account_id: int,
        amount: Decimal
    ) -> Decimal:
        """
        Credit account balance.

        Args:
            account_id: Account ID
            amount: Amount to credit

        Returns:
            New balance
        """
        sql = """
            UPDATE ACCOUNTS
            SET ACC_BALANCE = ACC_BALANCE + :amount
            WHERE ACC_ID = :account_id
        """
        await self.pool.execute(sql, {
            "account_id": account_id,
            "amount": amount
        })

        new_balance = await self.get_balance(account_id)
        logger.info(
            f"Credited {amount} to account {account_id}, "
            f"new balance: {new_balance}"
        )

        return new_balance

    # ========================================================================
    # Connection Limit Operations
    # ========================================================================

    async def get_max_connections(self, account_id: int) -> Optional[int]:
        """
        Get maximum EPP connections for account.

        Args:
            account_id: Account ID

        Returns:
            Max connections or None if unlimited
        """
        sql = """
            SELECT ACC_EPP_MAX_CONNECTIONS
            FROM ACCOUNTS WHERE ACC_ID = :account_id
        """
        result = await self.pool.query_value(sql, {"account_id": account_id})
        return int(result) if result else None

    async def get_active_connection_count(self, account_id: int) -> int:
        """
        Get current active connection count for account.

        Args:
            account_id: Account ID

        Returns:
            Number of active connections
        """
        sql = """
            SELECT COUNT(*) FROM CONNECTIONS
            WHERE CNN_ACCOUNT_ID = :account_id
              AND CNN_STATUS = 'OPEN'
        """
        result = await self.pool.query_value(sql, {"account_id": account_id})
        return int(result) if result else 0

    async def can_connect(self, account_id: int) -> bool:
        """
        Check if account can open a new connection.

        Args:
            account_id: Account ID

        Returns:
            True if connection allowed
        """
        max_conn = await self.get_max_connections(account_id)
        if max_conn is None:
            logger.info(f"Account {account_id}: No connection limit set")
            return True  # No limit

        current = await self.get_active_connection_count(account_id)
        logger.info(f"Account {account_id}: {current} open connections, max allowed: {max_conn}")
        return current < max_conn

    # ========================================================================
    # Password Utilities
    # ========================================================================

    def _hash_password(self, username: str, password: str) -> str:
        """
        Hash a password for storage.

        Uses ARI's algorithm: MD5(username + '/' + password)

        Args:
            username: Username
            password: Plain text password

        Returns:
            Hashed password (32 char hex string)
        """
        # ARI algorithm: MD5(username || '/' || password)
        return hashlib.md5((username + '/' + password).encode()).hexdigest()

    def _verify_password(self, username: str, password: str, stored_hash: str) -> bool:
        """
        Verify a password against stored hash.

        Uses timing-safe comparison to prevent timing attacks.
        Compares in uppercase for compatibility with ARI database.

        Args:
            username: Username
            password: Plain text password
            stored_hash: Stored hash to compare against

        Returns:
            True if password matches
        """
        computed_hash = self._hash_password(username, password).upper()
        return hmac.compare_digest(computed_hash, stored_hash.upper())


# Global repository instance
_account_repo: Optional[AccountRepository] = None


async def get_account_repo() -> AccountRepository:
    """Get or create global account repository."""
    global _account_repo
    if _account_repo is None:
        pool = await get_pool()
        _account_repo = AccountRepository(pool)
    return _account_repo
