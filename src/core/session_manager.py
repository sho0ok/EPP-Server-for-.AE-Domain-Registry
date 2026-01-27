"""
Session Manager

Manages EPP sessions including:
- Session creation and tracking
- Connection logging
- Authentication state
- Session validation and cleanup
- Session statistics
- Rate limiting integration
"""

import logging
import socket
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.database.repositories.transaction_repo import get_transaction_repo, TransactionRepository
from src.database.repositories.account_repo import get_account_repo, AccountRepository
from src.utils.rate_limiter import SessionStats, get_rate_limiter

logger = logging.getLogger("epp.session")


@dataclass
class SessionInfo:
    """Information about an active EPP session."""
    # Connection info
    connection_id: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    server_name: str
    connect_time: datetime

    # Session info (populated after login)
    session_id: Optional[int] = None
    user_id: Optional[int] = None
    account_id: Optional[int] = None
    client_id: Optional[str] = None  # EPP clID
    username: Optional[str] = None

    # State
    authenticated: bool = False
    login_time: Optional[datetime] = None
    last_activity: datetime = field(default_factory=datetime.utcnow)

    # Session options
    language: str = "en"
    version: str = "1.0"
    object_uris: List[str] = field(default_factory=list)
    extension_uris: List[str] = field(default_factory=list)

    # Statistics
    command_count: int = 0
    login_failures: int = 0

    # Detailed session statistics
    stats: SessionStats = field(default_factory=SessionStats)

    def record_command(self, command_type: str, success: bool = True) -> None:
        """Record a command execution with statistics."""
        self.command_count += 1
        self.last_activity = datetime.utcnow()
        self.stats.record_command(command_type, success)

    def record_bytes(self, sent: int = 0, received: int = 0) -> None:
        """Record bytes transferred."""
        self.stats.record_bytes(sent, received)

    def get_session_stats(self) -> Dict[str, Any]:
        """Get comprehensive session statistics."""
        return {
            "session_id": self.session_id,
            "client_id": self.client_id,
            "client_ip": self.client_ip,
            "authenticated": self.authenticated,
            "login_time": self.login_time.isoformat() if self.login_time else None,
            "login_failures": self.login_failures,
            **self.stats.to_dict()
        }


class SessionManager:
    """
    Manages EPP sessions and connection lifecycle.

    Responsibilities:
    - Create connection records on connect
    - Authenticate users on login
    - Create session records on successful login
    - Track session state
    - Log all operations
    - Clean up on disconnect
    """

    def __init__(
        self,
        server_name: str = "epp.aeda.ae",
        server_port: int = 700
    ):
        """
        Initialize session manager.

        Args:
            server_name: Server hostname for logging
            server_port: Server port for logging
        """
        self.server_name = server_name
        self.server_port = server_port
        self._server_ip = self._get_server_ip()
        self._transaction_repo: Optional[TransactionRepository] = None
        self._account_repo: Optional[AccountRepository] = None

    def _get_server_ip(self) -> str:
        """Get server's IP address."""
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except Exception:
            return "127.0.0.1"

    async def _get_repos(self) -> None:
        """Initialize repository references."""
        if self._transaction_repo is None:
            self._transaction_repo = await get_transaction_repo()
        if self._account_repo is None:
            self._account_repo = await get_account_repo()

    async def create_session_info(
        self,
        client_ip: str,
        client_port: int
    ) -> SessionInfo:
        """
        Create a new session info object for a connection.

        Note: This does not create database records yet.
        Database records are created during login.

        Args:
            client_ip: Client IP address
            client_port: Client port

        Returns:
            SessionInfo object
        """
        return SessionInfo(
            connection_id=0,  # Will be set on login
            client_ip=client_ip,
            client_port=client_port,
            server_ip=self._server_ip,
            server_port=self.server_port,
            server_name=self.server_name,
            connect_time=datetime.utcnow()
        )

    async def authenticate(
        self,
        session: SessionInfo,
        username: str,
        password: str,
        version: str = "1.0",
        language: str = "en",
        object_uris: Optional[List[str]] = None,
        extension_uris: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Authenticate a user and establish session.

        Args:
            session: Session info object
            username: EPP username (clID)
            password: Password
            version: EPP version
            language: Session language
            object_uris: Requested object URIs
            extension_uris: Requested extension URIs

        Returns:
            Dict with:
                - success: bool
                - code: EPP response code
                - message: Response message
        """
        await self._get_repos()

        # Validate credentials
        user_data = await self._account_repo.validate_credentials(username, password)

        if not user_data:
            session.login_failures += 1
            logger.warning(
                f"Login failed for {username} from {session.client_ip} "
                f"(attempt {session.login_failures})"
            )
            return {
                "success": False,
                "code": 2200,
                "message": "Authentication error"
            }

        account = user_data["account"]
        account_id = account["ACC_ID"]
        user_id = user_data["USR_ID"]

        # Check IP whitelist
        if not await self._account_repo.check_ip_whitelist(account_id, session.client_ip):
            logger.warning(
                f"IP {session.client_ip} not whitelisted for account {account_id}"
            )
            return {
                "success": False,
                "code": 2200,
                "message": "Authentication error: IP address not authorized"
            }

        # Check connection limit
        if not await self._account_repo.can_connect(account_id):
            logger.warning(
                f"Connection limit exceeded for account {account_id}"
            )
            return {
                "success": False,
                "code": 2502,
                "message": "Session limit exceeded; server closing connection"
            }

        # Create connection record
        connection_id = await self._transaction_repo.create_connection(
            account_id=account_id,
            user_id=user_id,
            server_name=self.server_name,
            server_ip=self._server_ip,
            server_port=self.server_port,
            client_ip=session.client_ip,
            client_port=session.client_port
        )

        # Create session record
        session_id = await self._transaction_repo.create_session(
            user_id=user_id,
            connection_id=connection_id,
            client_ip=session.client_ip,
            lang=language,
            object_uris=",".join(object_uris) if object_uris else None,
            extension_uris=",".join(extension_uris) if extension_uris else None
        )

        # Update session info
        session.connection_id = connection_id
        session.session_id = session_id
        session.user_id = user_id
        session.account_id = account_id
        session.client_id = account["ACC_CLIENT_ID"] or username
        session.username = username
        session.authenticated = True
        session.login_time = datetime.utcnow()
        session.last_activity = datetime.utcnow()
        session.version = version
        session.language = language
        session.object_uris = object_uris or []
        session.extension_uris = extension_uris or []

        logger.info(
            f"User {username} (account {account_id}) logged in from {session.client_ip}"
        )

        return {
            "success": True,
            "code": 1000,
            "message": "Command completed successfully"
        }

    async def logout(
        self,
        session: SessionInfo,
        reason: str = "Normal logout"
    ) -> None:
        """
        End a session gracefully.

        Args:
            session: Session info object
            reason: Logout reason for logging
        """
        await self._get_repos()

        if session.session_id:
            await self._transaction_repo.end_session(
                session_id=session.session_id,
                reason=reason
            )

        if session.connection_id:
            await self._transaction_repo.end_connection(
                conn_id=session.connection_id,
                reason=reason
            )

        logger.info(
            f"User {session.username} logged out from {session.client_ip}: {reason}"
        )

        # Clear session state
        session.authenticated = False
        session.session_id = None

    async def disconnect(
        self,
        session: SessionInfo,
        reason: str = "Connection closed"
    ) -> None:
        """
        Handle unexpected disconnection.

        Args:
            session: Session info object
            reason: Disconnect reason
        """
        await self._get_repos()

        if session.session_id:
            await self._transaction_repo.end_session(
                session_id=session.session_id,
                reason=reason
            )

        if session.connection_id:
            await self._transaction_repo.end_connection(
                conn_id=session.connection_id,
                reason=reason
            )

        if session.username:
            logger.info(
                f"User {session.username} disconnected from {session.client_ip}: {reason}"
            )

    async def touch(self, session: SessionInfo) -> None:
        """
        Update session last activity time.

        Args:
            session: Session info object
        """
        session.last_activity = datetime.utcnow()

        if session.session_id:
            await self._get_repos()
            await self._transaction_repo.touch_session(session.session_id)

    async def log_command(
        self,
        session: SessionInfo,
        command: str,
        client_ref: Optional[str] = None,
        roid: Optional[str] = None
    ) -> int:
        """
        Log start of a command.

        Args:
            session: Session info object
            command: Command name
            client_ref: Client transaction ID (clTRID)
            roid: Affected object ROID

        Returns:
            Transaction ID for completing the log
        """
        await self._get_repos()

        session.command_count += 1

        trn_id = await self._transaction_repo.log_transaction(
            command=command,
            connection_id=session.connection_id if session.connection_id else None,
            session_id=session.session_id,
            account_id=session.account_id,
            user_id=session.user_id,
            client_ref=client_ref,
            roid=roid
        )

        return trn_id

    async def complete_command(
        self,
        trn_id: int,
        response_code: int,
        response_message: Optional[str] = None,
        amount: Optional[Any] = None,
        balance: Optional[Any] = None,
        audit_log: Optional[str] = None,
        start_time: Optional[datetime] = None
    ) -> None:
        """
        Complete command logging.

        Args:
            trn_id: Transaction ID from log_command
            response_code: EPP response code
            response_message: Response message
            amount: Transaction amount (for billing)
            balance: Account balance after transaction
            audit_log: Audit details
            start_time: Command start time (for calculating duration)
        """
        await self._get_repos()

        app_time = None
        if start_time:
            delta = datetime.utcnow() - start_time
            app_time = int(delta.total_seconds() * 1000)

        await self._transaction_repo.complete_transaction(
            trn_id=trn_id,
            response_code=response_code,
            response_message=response_message,
            amount=amount,
            balance=balance,
            audit_log=audit_log,
            application_time=app_time
        )

    async def check_rate_limit(
        self,
        session: SessionInfo
    ) -> tuple:
        """
        Check if the session is within rate limits.

        Args:
            session: Session info object

        Returns:
            Tuple of (allowed, reason if not allowed)
        """
        rate_limiter = get_rate_limiter()
        if rate_limiter is None:
            return True, None

        return await rate_limiter.check_rate_limit(
            client_ip=session.client_ip,
            account_id=session.account_id
        )

    async def record_rate_limit(
        self,
        session: SessionInfo
    ) -> None:
        """
        Record a command for rate limiting tracking.

        Args:
            session: Session info object
        """
        rate_limiter = get_rate_limiter()
        if rate_limiter is not None:
            await rate_limiter.record_command(
                client_ip=session.client_ip,
                account_id=session.account_id
            )

    def is_authenticated(self, session: SessionInfo) -> bool:
        """Check if session is authenticated."""
        return session.authenticated and session.session_id is not None

    def get_client_id(self, session: SessionInfo) -> Optional[str]:
        """Get the client ID (clID) for the session."""
        return session.client_id


# Global session manager instance
_session_manager: Optional[SessionManager] = None


def initialize_session_manager(
    server_name: str = "epp.aeda.ae",
    server_port: int = 700
) -> SessionManager:
    """
    Initialize global session manager.

    Args:
        server_name: Server hostname
        server_port: Server port

    Returns:
        SessionManager instance
    """
    global _session_manager
    _session_manager = SessionManager(
        server_name=server_name,
        server_port=server_port
    )
    return _session_manager


def get_session_manager() -> SessionManager:
    """
    Get global session manager.

    Returns:
        SessionManager instance

    Raises:
        RuntimeError: If not initialized
    """
    if _session_manager is None:
        raise RuntimeError("Session manager not initialized")
    return _session_manager
