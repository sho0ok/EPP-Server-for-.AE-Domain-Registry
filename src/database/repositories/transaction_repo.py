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


# Mapping from EPP response codes to ARI internal response codes
# The TRANSACTIONS.TRN_RESPONSE_CODE column references RESPONSE_CODES.RCO_CODE
# which contains ARI internal codes, not EPP codes.
# The portal uses these ARI codes to determine success/failure.
# ARI codes 100-104 are SUCCESS codes, codes >= 105 are ERROR codes.
#
# These mappings are based on the pop_response_codes.sql population script.
EPP_TO_ARI_RESPONSE_CODE = {
    # Success codes (100-104 range indicates success in ARI)
    1000: 100,   # ok - Command completed successfully
    1001: 101,   # successful_pending - Command completed successfully; action pending
    1300: 103,   # successful_no_messages - No messages
    1301: 102,   # successful_messages - Messages available
    1500: 100,   # Command completed successfully; ending session (mapped to ok)

    # Protocol Syntax Errors (2000-2099) - ARI uses 209 for invalid_command
    2000: 209,   # invalid_command - Unknown command
    2001: 209,   # Command syntax error (mapped to invalid_command)
    2002: 20,    # operation_not_supported_in_zone / Command use error
    2003: 206,   # missing_extensions - Required parameter missing
    2004: 30,    # field_value_too_long - Parameter value range error
    2005: 30,    # field_value_too_long - Parameter value syntax error

    # Implementation-specific Rules Errors (2100-2199)
    2100: 202,   # unimplemented_protocol
    2101: 203,   # unimplemented_command
    2102: 204,   # unimplemented_option
    2103: 205,   # unimplemented_extension
    2104: 216,   # billing_error
    2105: 216,   # Object is not eligible for renewal (billing related)
    2106: 216,   # Object is not eligible for transfer (billing related)

    # Security Errors (2200-2299)
    2200: 208,   # invalid_authorisation - Authentication error
    2201: 221,   # authorized_registry - Authorization error
    2202: 208,   # invalid_authorisation - Invalid authorization information

    # Data Management Errors (2300-2399)
    2300: 213,   # object_pending_transfer
    2301: 214,   # object_not_pending_transfer
    2302: 210,   # object_does_not_exist (for "Object exists" we use a generic error)
    2303: 210,   # object_does_not_exist
    2304: 212,   # status_prohibits_operation
    2305: 212,   # status_prohibits_operation (Object association prohibits operation)
    2306: 30,    # field_value_too_long - Parameter value policy error
    2307: 203,   # unimplemented_command - Unimplemented object service
    2308: 218,   # object_locked - Data management policy violation

    # Server Errors (2400-2599)
    2400: 215,   # unknown_error - Command failed
    2500: 300,   # connection_exists - Command failed; server closing connection
    2501: 208,   # invalid_authorisation - Authentication error; server closing connection
    2502: 301,   # connection_limit_exceeded - Session limit exceeded
}


def epp_to_ari_response_code(epp_code: int) -> int:
    """
    Convert EPP response code to ARI internal response code.

    The ARI database RESPONSE_CODES table uses internal codes (100, 200, etc.)
    that map to EPP codes. The portal determines success based on these internal codes.
    ARI codes 100-104 indicate success; all other codes indicate failure.

    Args:
        epp_code: EPP response code (1000, 2000, etc.)

    Returns:
        ARI internal response code (100 for success, 200+ for errors)
    """
    if epp_code in EPP_TO_ARI_RESPONSE_CODE:
        return EPP_TO_ARI_RESPONSE_CODE[epp_code]

    # Fallback: map success vs error based on EPP code range
    if 1000 <= epp_code < 2000:
        return 100  # Map unknown success to 'ok'

    # For unknown error codes, use 215 (unknown_error) which maps to EPP 2400
    logger.warning(f"Unknown EPP response code: {epp_code}, mapping to ARI 215 (unknown_error)")
    return 215  # unknown_error


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
            status="CLOSE"
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
            status="CLOSE"
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
            response_code: EPP response code (will be converted to ARI internal code)
            response_message: Response message
            amount: Transaction amount (if billing)
            balance: Account balance after transaction
            audit_log: Audit details
            application_time: Processing time in milliseconds
        """
        # Convert EPP response code to ARI internal code
        # The RESPONSE_CODES table uses internal codes (100=ok, 200+=errors)
        ari_response_code = epp_to_ari_response_code(response_code)

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
            "response_code": ari_response_code,
            "response_message": response_message[:4000] if response_message else None,
            "amount": amount,
            "balance": balance,
            "audit_log": audit_log[:4000] if audit_log else None,
            "application_time": application_time
        })

        logger.debug(f"Completed transaction {trn_id}: EPP code={response_code} -> ARI code={ari_response_code}")

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

        Args:
            response_code: EPP response code (will be converted to ARI internal code)

        Returns:
            Transaction ID
        """
        trn_id = await self.pool.get_next_sequence("TRN_ID_SEQ")
        now = datetime.utcnow()

        # Convert EPP response code to ARI internal code
        ari_response_code = epp_to_ari_response_code(response_code)

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
            "response_code": ari_response_code,
            "response_message": response_message[:4000] if response_message else None,
            "amount": amount,
            "balance": balance,
            "audit_log": audit_log[:4000] if audit_log else None,
            "application_time": application_time
        })

        return trn_id

    async def cleanup_stale_connections(self, server_name: str) -> int:
        """
        Close all stale OPEN connections on startup.

        This handles the case where the server crashed without properly
        closing connections, leaving orphaned OPEN records in the database.

        Args:
            server_name: Server name (for logging)

        Returns:
            Number of connections cleaned up
        """
        # Close ALL open connections - they're stale since we just started
        # Note: CNN_STATUS is VARCHAR2(5), so use 'CLOSE' not 'CLOSE'
        sql = """
            UPDATE CONNECTIONS
            SET CNN_STATUS = 'CLOSE',
                CNN_END_TIME = :end_time
            WHERE CNN_STATUS = 'OPEN'
        """
        result = await self.pool.execute(sql, {
            "end_time": datetime.utcnow()
        })

        # Also close all orphaned sessions
        # Note: SES_STATUS is VARCHAR2(5), so use 'CLOSE' not 'CLOSE'
        sql_sessions = """
            UPDATE SESSIONS
            SET SES_STATUS = 'CLOSE',
                SES_END_TIME = :end_time
            WHERE SES_STATUS = 'OPEN'
        """
        await self.pool.execute(sql_sessions, {
            "end_time": datetime.utcnow()
        })

        logger.info(f"Cleaned up all stale OPEN connections on server startup")
        return result if result else 0


# Global repository instance
_transaction_repo: Optional[TransactionRepository] = None


async def get_transaction_repo() -> TransactionRepository:
    """Get or create global transaction repository."""
    global _transaction_repo
    if _transaction_repo is None:
        pool = await get_pool()
        _transaction_repo = TransactionRepository(pool)
    return _transaction_repo
