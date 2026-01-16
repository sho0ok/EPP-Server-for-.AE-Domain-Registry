"""
Transaction Repository

Handles logging to CONNECTIONS, SESSIONS, and TRANSACTIONS tables.
All EPP operations must be logged for audit compliance.
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional
from decimal import Decimal

from src.database.connection import get_pool, DatabasePool

logger = logging.getLogger("epp.database.transaction")


class TransactionRepository:
    """
    Repository for connection, session, and transaction logging.

    All EPP connections, sessions, and commands are logged to the database
    for audit and compliance purposes.
    """

    def __init__(self, pool: DatabasePool):
        """Initialize with database pool."""
        self.pool = pool

    # ========================================================================
    # Connection Operations
    # ========================================================================

    async def create_connection(
        self,
        account_id: int,
        user_id: int,
        server_name: str,
        server_ip: str,
        server_port: int,
        client_ip: str,
        client_port: int
    ) -> int:
        """
        Create a new connection record.

        Args:
            account_id: FK to ACCOUNTS
            user_id: FK to USERS
            server_name: Server hostname
            server_ip: Server IP address
            server_port: Server port
            client_ip: Client IP address (IMPORTANT for audit)
            client_port: Client port

        Returns:
            New connection ID
        """
        # Get next sequence value
        conn_id = await self.pool.get_next_sequence("CNN_ID_SEQ")

        sql = """
            INSERT INTO CONNECTIONS (
                CNN_ID, CNN_ACCOUNT_ID, CNN_USER_ID,
                CNN_SERVER_NAME, CNN_SERVER_IP, CNN_SERVER_PORT,
                CNN_CLIENT_IP, CNN_CLIENT_PORT,
                CNN_START_TIME, CNN_LOGIN_FAILURES, CNN_STATUS
            ) VALUES (
                :conn_id, :account_id, :user_id,
                :server_name, :server_ip, :server_port,
                :client_ip, :client_port,
                :start_time, 0, 'OPEN'
            )
        """

        await self.pool.execute(sql, {
            "conn_id": conn_id,
            "account_id": account_id,
            "user_id": user_id,
            "server_name": server_name,
            "server_ip": server_ip,
            "server_port": server_port,
            "client_ip": client_ip,
            "client_port": client_port,
            "start_time": datetime.utcnow()
        })

        logger.debug(f"Created connection {conn_id} for client {client_ip}")
        return conn_id

    async def update_connection(
        self,
        conn_id: int,
        end_time: Optional[datetime] = None,
        end_reason: Optional[str] = None,
        status: Optional[str] = None,
        login_failures: Optional[int] = None
    ) -> None:
        """
        Update a connection record.

        Args:
            conn_id: Connection ID to update
            end_time: Connection end time
            end_reason: Reason for ending connection
            status: New status
            login_failures: Number of failed login attempts
        """
        updates = []
        params = {"conn_id": conn_id}

        if end_time is not None:
            updates.append("CNN_END_TIME = :end_time")
            params["end_time"] = end_time

        if end_reason is not None:
            updates.append("CNN_END_REASON = :end_reason")
            params["end_reason"] = end_reason[:100]  # Truncate to column size

        if status is not None:
            updates.append("CNN_STATUS = :status")
            params["status"] = status

        if login_failures is not None:
            updates.append("CNN_LOGIN_FAILURES = :login_failures")
            params["login_failures"] = login_failures

        if not updates:
            return

        sql = f"UPDATE CONNECTIONS SET {', '.join(updates)} WHERE CNN_ID = :conn_id"
        await self.pool.execute(sql, params)
        logger.debug(f"Updated connection {conn_id}")

    async def end_connection(
        self,
        conn_id: int,
        reason: str = "Normal disconnect"
    ) -> None:
        """
        End a connection (convenience method).

        Args:
            conn_id: Connection ID
            reason: End reason
        """
        await self.update_connection(
            conn_id=conn_id,
            end_time=datetime.utcnow(),
            end_reason=reason,
            status="CLOSED"
        )

    async def increment_login_failures(self, conn_id: int) -> int:
        """
        Increment login failure count.

        Args:
            conn_id: Connection ID

        Returns:
            New failure count
        """
        sql = """
            UPDATE CONNECTIONS
            SET CNN_LOGIN_FAILURES = CNN_LOGIN_FAILURES + 1
            WHERE CNN_ID = :conn_id
            RETURNING CNN_LOGIN_FAILURES INTO :new_count
        """
        # For Oracle, we need a different approach
        await self.pool.execute(
            "UPDATE CONNECTIONS SET CNN_LOGIN_FAILURES = CNN_LOGIN_FAILURES + 1 WHERE CNN_ID = :conn_id",
            {"conn_id": conn_id}
        )

        result = await self.pool.query_value(
            "SELECT CNN_LOGIN_FAILURES FROM CONNECTIONS WHERE CNN_ID = :conn_id",
            {"conn_id": conn_id}
        )
        return int(result) if result else 0

    # ========================================================================
    # Session Operations
    # ========================================================================

    async def create_session(
        self,
        user_id: int,
        connection_id: int,
        client_ip: str,
        lang: str = "en",
        object_uris: Optional[str] = None,
        extension_uris: Optional[str] = None
    ) -> int:
        """
        Create a new session record.

        Args:
            user_id: FK to USERS
            connection_id: FK to CONNECTIONS
            client_ip: Client IP address
            lang: Session language
            object_uris: Supported object URIs (comma-separated)
            extension_uris: Supported extension URIs (comma-separated)

        Returns:
            New session ID
        """
        session_id = await self.pool.get_next_sequence("SES_ID_SEQ")
        now = datetime.utcnow()

        sql = """
            INSERT INTO SESSIONS (
                SES_ID, SES_USER_ID, SES_CONNECTION_ID, SES_CLIENT_IP,
                SES_START_TIME, SES_LAST_USED, SES_STATUS, SES_LANG,
                SES_OBJECT_URIS, SES_EXTENSION_URIS
            ) VALUES (
                :session_id, :user_id, :connection_id, :client_ip,
                :start_time, :last_used, 'OPEN', :lang,
                :object_uris, :extension_uris
            )
        """

        await self.pool.execute(sql, {
            "session_id": session_id,
            "user_id": user_id,
            "connection_id": connection_id,
            "client_ip": client_ip,
            "start_time": now,
            "last_used": now,
            "lang": lang,
            "object_uris": object_uris,
            "extension_uris": extension_uris
        })

        logger.debug(f"Created session {session_id} for user {user_id}")
        return session_id

    async def update_session(
        self,
        session_id: int,
        last_used: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        end_reason: Optional[str] = None,
        status: Optional[str] = None
    ) -> None:
        """
        Update a session record.

        Args:
            session_id: Session ID to update
            last_used: Last activity time
            end_time: Session end time
            end_reason: Reason for ending session
            status: New status
        """
        updates = []
        params = {"session_id": session_id}

        if last_used is not None:
            updates.append("SES_LAST_USED = :last_used")
            params["last_used"] = last_used

        if end_time is not None:
            updates.append("SES_END_TIME = :end_time")
            params["end_time"] = end_time

        if end_reason is not None:
            updates.append("SES_END_REASON = :end_reason")
            params["end_reason"] = end_reason[:100]

        if status is not None:
            updates.append("SES_STATUS = :status")
            params["status"] = status

        if not updates:
            return

        sql = f"UPDATE SESSIONS SET {', '.join(updates)} WHERE SES_ID = :session_id"
        await self.pool.execute(sql, params)
        logger.debug(f"Updated session {session_id}")

    async def end_session(
        self,
        session_id: int,
        reason: str = "Normal logout"
    ) -> None:
        """
        End a session (convenience method).

        Args:
            session_id: Session ID
            reason: End reason
        """
        await self.update_session(
            session_id=session_id,
            end_time=datetime.utcnow(),
            end_reason=reason,
            status="CLOSED"
        )

    async def touch_session(self, session_id: int) -> None:
        """
        Update session last used time.

        Args:
            session_id: Session ID
        """
        await self.update_session(
            session_id=session_id,
            last_used=datetime.utcnow()
        )

    # ========================================================================
    # Transaction Operations
    # ========================================================================

    async def log_transaction(
        self,
        command: str,
        connection_id: Optional[int] = None,
        session_id: Optional[int] = None,
        account_id: Optional[int] = None,
        user_id: Optional[int] = None,
        client_ref: Optional[str] = None,
        roid: Optional[str] = None
    ) -> int:
        """
        Start logging a transaction.

        Args:
            command: EPP command name
            connection_id: FK to CONNECTIONS
            session_id: FK to SESSIONS
            account_id: FK to ACCOUNTS
            user_id: FK to USERS
            client_ref: Client transaction ID (clTRID)
            roid: Affected object ROID

        Returns:
            New transaction ID
        """
        trn_id = await self.pool.get_next_sequence("TRN_ID_SEQ")

        sql = """
            INSERT INTO TRANSACTIONS (
                TRN_ID, TRN_CONNECTION_ID, TRN_SESSION_ID,
                TRN_ACCOUNT_ID, TRN_USER_ID, TRN_COMMAND,
                TRN_CLIENT_REF, TRN_ROID, TRN_START_TIME
            ) VALUES (
                :trn_id, :connection_id, :session_id,
                :account_id, :user_id, :command,
                :client_ref, :roid, :start_time
            )
        """

        await self.pool.execute(sql, {
            "trn_id": trn_id,
            "connection_id": connection_id,
            "session_id": session_id,
            "account_id": account_id,
            "user_id": user_id,
            "command": command[:48],  # Truncate to column size
            "client_ref": client_ref[:64] if client_ref else None,
            "roid": roid,
            "start_time": datetime.utcnow()
        })

        logger.debug(f"Started transaction {trn_id}: {command}")
        return trn_id

    async def complete_transaction(
        self,
        trn_id: int,
        response_code: int,
        response_message: Optional[str] = None,
        amount: Optional[Decimal] = None,
        balance: Optional[Decimal] = None,
        audit_log: Optional[str] = None,
        application_time: Optional[int] = None
    ) -> None:
        """
        Complete a transaction record.

        Args:
            trn_id: Transaction ID
            response_code: EPP response code
            response_message: Response message
            amount: Transaction amount (if billing)
            balance: Account balance after transaction
            audit_log: Audit details
            application_time: Processing time in milliseconds
        """
        sql = """
            UPDATE TRANSACTIONS SET
                TRN_END_TIME = :end_time,
                TRN_RESPONSE_CODE = :response_code,
                TRN_RESPONSE_MESSAGE = :response_message,
                TRN_AMOUNT = :amount,
                TRN_BALANCE = :balance,
                TRN_AUDIT_LOG = :audit_log,
                TRN_APPLICATION_TIME = :application_time
            WHERE TRN_ID = :trn_id
        """

        await self.pool.execute(sql, {
            "trn_id": trn_id,
            "end_time": datetime.utcnow(),
            "response_code": response_code,
            "response_message": response_message[:4000] if response_message else None,
            "amount": amount,
            "balance": balance,
            "audit_log": audit_log[:4000] if audit_log else None,
            "application_time": application_time
        })

        logger.debug(f"Completed transaction {trn_id}: code={response_code}")

    async def log_complete_transaction(
        self,
        command: str,
        response_code: int,
        connection_id: Optional[int] = None,
        session_id: Optional[int] = None,
        account_id: Optional[int] = None,
        user_id: Optional[int] = None,
        client_ref: Optional[str] = None,
        roid: Optional[str] = None,
        response_message: Optional[str] = None,
        amount: Optional[Decimal] = None,
        balance: Optional[Decimal] = None,
        audit_log: Optional[str] = None,
        application_time: Optional[int] = None
    ) -> int:
        """
        Log a complete transaction in one call.

        Convenience method that creates and completes a transaction record.

        Returns:
            Transaction ID
        """
        trn_id = await self.pool.get_next_sequence("TRN_ID_SEQ")
        now = datetime.utcnow()

        sql = """
            INSERT INTO TRANSACTIONS (
                TRN_ID, TRN_CONNECTION_ID, TRN_SESSION_ID,
                TRN_ACCOUNT_ID, TRN_USER_ID, TRN_COMMAND,
                TRN_CLIENT_REF, TRN_ROID, TRN_START_TIME,
                TRN_END_TIME, TRN_RESPONSE_CODE, TRN_RESPONSE_MESSAGE,
                TRN_AMOUNT, TRN_BALANCE, TRN_AUDIT_LOG, TRN_APPLICATION_TIME
            ) VALUES (
                :trn_id, :connection_id, :session_id,
                :account_id, :user_id, :command,
                :client_ref, :roid, :start_time,
                :end_time, :response_code, :response_message,
                :amount, :balance, :audit_log, :application_time
            )
        """

        await self.pool.execute(sql, {
            "trn_id": trn_id,
            "connection_id": connection_id,
            "session_id": session_id,
            "account_id": account_id,
            "user_id": user_id,
            "command": command[:48],
            "client_ref": client_ref[:64] if client_ref else None,
            "roid": roid,
            "start_time": now,
            "end_time": now,
            "response_code": response_code,
            "response_message": response_message[:4000] if response_message else None,
            "amount": amount,
            "balance": balance,
            "audit_log": audit_log[:4000] if audit_log else None,
            "application_time": application_time
        })

        return trn_id


# Global repository instance
_transaction_repo: Optional[TransactionRepository] = None


async def get_transaction_repo() -> TransactionRepository:
    """Get or create global transaction repository."""
    global _transaction_repo
    if _transaction_repo is None:
        pool = await get_pool()
        _transaction_repo = TransactionRepository(pool)
    return _transaction_repo
