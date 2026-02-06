"""
Base Command Handler

Provides base class for all EPP command handlers with:
- Transaction logging
- Error handling
- Response building
- Authorization checks
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional
from decimal import Decimal

from src.core.session_manager import SessionInfo, get_session_manager
from src.core.xml_processor import EPPCommand
from src.utils.response_builder import get_response_builder, ResponseBuilder

logger = logging.getLogger("epp.commands")


# Mapping from EPP command format to ARI database command names
# EPP uses "object:action" but ARI uses "Object Action" (title case with space)
EPP_TO_ARI_COMMAND = {
    "domain:check": "Domain Check",
    "domain:info": "Domain View",
    "domain:create": "Domain Create",
    "domain:delete": "Domain Delete",
    "domain:update": "Domain Update",
    "domain:renew": "Domain Renew",
    "domain:transfer": "Domain Transfer",
    "contact:check": "Contact Check",
    "contact:info": "Contact View",
    "contact:create": "Contact Create",
    "contact:delete": "Contact Delete",
    "contact:update": "Contact Update",
    "contact:transfer": "Contact Transfer",
    "host:check": "Host Check",
    "host:info": "Host View",
    "host:create": "Host Create",
    "host:delete": "Host Delete",
    "host:update": "Host Update",
    "session:login": "Login",
    "session:logout": "Logout",
    "poll:request": "Message Request",
    "poll:ack": "Message Acknowledge",
}


def get_ari_command_name(epp_command: str) -> str:
    """
    Convert EPP command format to ARI database command name.

    Args:
        epp_command: EPP format like "domain:check"

    Returns:
        ARI format like "Domain Check"
    """
    # Check explicit mapping first
    if epp_command in EPP_TO_ARI_COMMAND:
        return EPP_TO_ARI_COMMAND[epp_command]

    # Fallback: convert "object:action" to "Object Action"
    parts = epp_command.split(":")
    if len(parts) == 2:
        return f"{parts[0].title()} {parts[1].title()}"

    return epp_command.title()


class CommandError(Exception):
    """Base exception for command errors."""

    def __init__(
        self,
        code: int,
        message: str,
        reason: Optional[str] = None,
        value: Optional[str] = None
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.reason = reason
        self.value = value


class AuthenticationError(CommandError):
    """Authentication required or failed."""

    def __init__(self, message: str = "Authentication error"):
        super().__init__(2200, message)


class AuthorizationError(CommandError):
    """Not authorized for this operation."""

    def __init__(self, message: str = "Authorization error"):
        super().__init__(2201, message)


class ObjectNotFoundError(CommandError):
    """Object does not exist."""

    def __init__(self, object_type: str, identifier: str):
        super().__init__(
            2303,
            f"Object does not exist",
            reason=f"The {object_type} '{identifier}' was not found"
        )


class ObjectExistsError(CommandError):
    """Object already exists."""

    def __init__(self, object_type: str, identifier: str):
        super().__init__(
            2302,
            f"Object exists",
            reason=f"The {object_type} '{identifier}' already exists"
        )


class ObjectStatusError(CommandError):
    """Object status prohibits operation."""

    def __init__(self, message: str = "Object status prohibits operation"):
        super().__init__(2304, message)


class ParameterError(CommandError):
    """Parameter value error."""

    def __init__(
        self,
        message: str = "Parameter value error",
        value: Optional[str] = None
    ):
        super().__init__(2005, message, value=value)


class BillingError(CommandError):
    """Billing/payment error."""

    def __init__(self, message: str = "Billing failure"):
        super().__init__(2104, message)


class BaseCommandHandler(ABC):
    """
    Base class for EPP command handlers.

    Provides common functionality:
    - Session validation
    - Transaction logging
    - Error handling
    - Response building
    """

    # Command name for logging
    command_name: str = "unknown"

    # Whether command requires authentication
    requires_auth: bool = True

    def __init__(self):
        """Initialize handler."""
        self._response_builder: Optional[ResponseBuilder] = None

    @property
    def response_builder(self) -> ResponseBuilder:
        """Get response builder."""
        if self._response_builder is None:
            self._response_builder = get_response_builder()
        return self._response_builder

    async def execute(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """
        Execute the command with full logging and error handling.

        Args:
            command: Parsed EPP command
            session: Session information

        Returns:
            XML response bytes
        """
        cl_trid = command.client_transaction_id
        start_time = datetime.utcnow()
        trn_id = None
        response_code = 2400  # Default to failure

        response_message = None  # Track error message for logging

        try:
            # Check authentication if required
            if self.requires_auth and not session.authenticated:
                raise AuthenticationError("Command use error: not logged in")

            # Get session manager for logging
            session_mgr = get_session_manager()

            # Log transaction start
            trn_id = await session_mgr.log_command(
                session=session,
                command=self.command_name,
                client_ref=cl_trid
            )

            # Execute the actual command
            response = await self.handle(command, session)
            response_code = 1000  # Success
            response_message = "ok"  # ARI stores 'ok' in TRN_RESPONSE_MESSAGE for code 100

            return response

        except CommandError as e:
            response_code = e.code
            response_message = e.message
            if e.reason:
                response_message = f"{e.message}: {e.reason}"
            logger.warning(
                f"Command {self.command_name} failed: [{e.code}] {response_message}"
            )
            return self.response_builder.build_error(
                code=e.code,
                message=e.message,
                cl_trid=cl_trid,
                reason=e.reason,
                value=e.value
            )

        except Exception as e:
            response_code = 2400
            response_message = f"Command failed: {str(e)}"
            logger.exception(f"Command {self.command_name} error: {e}")
            return self.response_builder.build_error(
                code=2400,
                message="Command failed",
                cl_trid=cl_trid
            )

        finally:
            # Complete transaction logging
            if trn_id and session.authenticated:
                try:
                    session_mgr = get_session_manager()
                    await session_mgr.complete_command(
                        trn_id=trn_id,
                        response_code=response_code,
                        response_message=response_message,
                        start_time=start_time
                    )
                except Exception as e:
                    logger.error(f"Failed to complete transaction log: {e}")

    @abstractmethod
    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """
        Handle the command (to be implemented by subclasses).

        Args:
            command: Parsed EPP command
            session: Session information

        Returns:
            XML response bytes
        """
        pass

    def success_response(
        self,
        cl_trid: Optional[str] = None,
        result_data: Any = None,
        code: int = 1000,
        message: Optional[str] = None,
        extensions: Any = None
    ) -> bytes:
        """
        Build a success response.

        Args:
            cl_trid: Client transaction ID
            result_data: Optional result data element
            code: Response code (default 1000)
            message: Optional custom message
            extensions: Optional extensions data (dict or XML element)

        Returns:
            XML response bytes
        """
        # Build extension XML if dict provided
        extensions_xml = None
        if extensions:
            if isinstance(extensions, dict):
                extensions_xml = self.response_builder.build_extensions_response(extensions)
            else:
                # Already an XML element
                extensions_xml = extensions

        return self.response_builder.build_response(
            code=code,
            message=message,
            cl_trid=cl_trid,
            result_data=result_data,
            extensions=extensions_xml
        )

    def error_response(
        self,
        code: int,
        cl_trid: Optional[str] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
        value: Optional[str] = None
    ) -> bytes:
        """
        Build an error response.

        Args:
            code: EPP error code
            cl_trid: Client transaction ID
            message: Error message
            reason: Extended error reason
            value: Value that caused error

        Returns:
            XML response bytes
        """
        return self.response_builder.build_error(
            code=code,
            message=message,
            cl_trid=cl_trid,
            reason=reason,
            value=value
        )


class ObjectCommandHandler(BaseCommandHandler):
    """
    Base class for object-specific commands (domain, contact, host).

    Adds object-specific functionality:
    - Object type identification
    - ROID tracking in transactions
    - Common validation
    - Transaction metadata (amount, balance, audit_log) for billing operations
    """

    # Object type (domain, contact, host)
    object_type: str = "unknown"

    # When True, the PL/SQL stored procedure handles transaction logging
    # internally (via transaction_t.start_transaction/end_transaction).
    # The execute() wrapper skips its own transaction logging to avoid duplicates.
    plsql_managed: bool = False

    def __init__(self):
        """Initialize handler with transaction metadata storage."""
        super().__init__()
        # Transaction metadata populated by handlers for logging
        # These values are passed to complete_command() for audit trail
        self._trn_amount: Optional[Decimal] = None
        self._trn_balance: Optional[Decimal] = None
        self._trn_audit_log: Optional[str] = None
        self._trn_roid: Optional[str] = None  # ROID created/affected by command
        self._trn_rate_id: Optional[int] = None  # FK to RATES table
        self._trn_comments: Optional[str] = None  # Comments (e.g., domain name)

    def set_transaction_data(
        self,
        amount: Optional[Decimal] = None,
        balance: Optional[Decimal] = None,
        roid: Optional[str] = None,
        audit_log: Optional[str] = None,
        rate_id: Optional[int] = None,
        comments: Optional[str] = None
    ) -> None:
        """
        Set transaction metadata for audit logging.

        Called by handlers (e.g., DomainCreate, DomainRenew) to store
        billing and audit information that will be logged to TRANSACTIONS table.

        Args:
            amount: Transaction amount (debit amount)
            balance: Account balance after transaction
            roid: ROID of created/affected object
            audit_log: Audit details (command parameters, etc.)
            rate_id: FK to RATES table (for billing operations)
            comments: Transaction comments (typically domain name)
        """
        if amount is not None:
            self._trn_amount = amount
        if balance is not None:
            self._trn_balance = balance
        if roid is not None:
            self._trn_roid = roid
        if audit_log is not None:
            self._trn_audit_log = audit_log
        if rate_id is not None:
            self._trn_rate_id = rate_id
        if comments is not None:
            self._trn_comments = comments

    async def execute(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """
        Execute with object-specific logging.

        If plsql_managed is True, the PL/SQL stored procedure handles
        transaction logging internally, so we skip our own logging.
        Otherwise, extracts ROID and logs transactions as before.
        """
        cl_trid = command.client_transaction_id

        # For PL/SQL-managed commands, skip our transaction logging
        # The stored procedure (e.g., epp_domain.domain_create) handles
        # everything internally including transaction_t management.
        if self.plsql_managed:
            try:
                if self.requires_auth and not session.authenticated:
                    raise AuthenticationError("Command use error: not logged in")

                response = await self.handle(command, session)
                return response

            except CommandError as e:
                logger.warning(
                    f"Command {self.object_type}:{self.command_name} failed: "
                    f"[{e.code}] {e.message}"
                )
                return self.response_builder.build_error(
                    code=e.code,
                    message=e.message,
                    cl_trid=cl_trid,
                    reason=e.reason,
                    value=e.value
                )

            except Exception as e:
                logger.exception(
                    f"Command {self.object_type}:{self.command_name} error: {e}"
                )
                return self.response_builder.build_error(
                    code=2400,
                    message="Command failed",
                    cl_trid=cl_trid
                )

        # Non-PL/SQL path: manual transaction logging
        start_time = datetime.utcnow()
        trn_id = None
        response_code = 2400
        response_message = None
        roid = None

        # Reset transaction metadata for this execution
        self._trn_amount = None
        self._trn_balance = None
        self._trn_audit_log = None
        self._trn_roid = None
        self._trn_rate_id = None
        self._trn_comments = None

        try:
            if self.requires_auth and not session.authenticated:
                raise AuthenticationError("Command use error: not logged in")

            session_mgr = get_session_manager()

            # Try to get ROID from command data (for existing objects)
            roid = await self.get_roid_from_command(command, session)

            # Convert EPP command format to ARI database format
            epp_cmd = f"{self.object_type}:{self.command_name}"
            ari_cmd = get_ari_command_name(epp_cmd)

            trn_id = await session_mgr.log_command(
                session=session,
                command=ari_cmd,
                client_ref=cl_trid,
                roid=roid
            )

            response = await self.handle(command, session)
            response_code = 1000
            response_message = "ok"  # ARI stores 'ok' in TRN_RESPONSE_MESSAGE for code 100

            return response

        except CommandError as e:
            response_code = e.code
            response_message = e.message
            if e.reason:
                response_message = f"{e.message}: {e.reason}"
            logger.warning(
                f"Command {self.object_type}:{self.command_name} failed: "
                f"[{e.code}] {response_message}"
            )
            return self.response_builder.build_error(
                code=e.code,
                message=e.message,
                cl_trid=cl_trid,
                reason=e.reason,
                value=e.value
            )

        except Exception as e:
            response_code = 2400
            response_message = f"Command failed: {str(e)}"
            logger.exception(
                f"Command {self.object_type}:{self.command_name} error: {e}"
            )
            return self.response_builder.build_error(
                code=2400,
                message="Command failed",
                cl_trid=cl_trid
            )

        finally:
            if trn_id and session.authenticated:
                try:
                    session_mgr = get_session_manager()
                    # Use handler-stored ROID if available (for create operations)
                    # Otherwise fall back to ROID from command lookup
                    final_roid = self._trn_roid or roid

                    # Update ROID in transaction if we now have it (e.g., after create)
                    if final_roid and final_roid != roid:
                        # Update the transaction record with the new ROID
                        from src.database.repositories.transaction_repo import get_transaction_repo
                        trn_repo = await get_transaction_repo()
                        await trn_repo.pool.execute(
                            "UPDATE TRANSACTIONS SET TRN_ROID = :roid WHERE TRN_ID = :trn_id",
                            {"roid": final_roid, "trn_id": trn_id}
                        )

                    await session_mgr.complete_command(
                        trn_id=trn_id,
                        response_code=response_code,
                        response_message=response_message,
                        amount=self._trn_amount,
                        balance=self._trn_balance,
                        audit_log=self._trn_audit_log,
                        start_time=start_time,
                        rate_id=self._trn_rate_id,
                        comments=self._trn_comments
                    )
                except Exception as e:
                    logger.error(f"Failed to complete transaction log: {e}")

    async def get_roid_from_command(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> Optional[str]:
        """
        Extract ROID from command for transaction logging.

        Override in subclasses to extract ROID from specific commands.

        Args:
            command: Parsed EPP command
            session: Session info

        Returns:
            ROID if available, None otherwise
        """
        return None

    def check_sponsorship(
        self,
        object_account_id: int,
        session: SessionInfo
    ) -> None:
        """
        Verify session account sponsors the object.

        Args:
            object_account_id: Account ID that sponsors the object
            session: Current session

        Raises:
            AuthorizationError: If not authorized
        """
        if session.account_id != object_account_id:
            raise AuthorizationError(
                f"Authorization error: object not sponsored by this registrar"
            )


class BillableCommandHandler(ObjectCommandHandler):
    """
    Base class for commands that involve billing.

    Adds:
    - Balance checking
    - Balance debiting
    - Transaction amount logging
    """

    async def check_balance(
        self,
        session: SessionInfo,
        amount: Decimal
    ) -> None:
        """
        Check if account has sufficient balance.

        Args:
            session: Session info
            amount: Required amount

        Raises:
            BillingError: If insufficient funds
        """
        from src.database.repositories.account_repo import get_account_repo

        account_repo = await get_account_repo()

        if not await account_repo.can_afford(session.account_id, amount):
            raise BillingError(
                f"Billing failure: insufficient funds (required: {amount})"
            )

    async def debit_account(
        self,
        session: SessionInfo,
        amount: Decimal
    ) -> Decimal:
        """
        Debit account balance.

        Args:
            session: Session info
            amount: Amount to debit

        Returns:
            New balance

        Raises:
            BillingError: If debit fails
        """
        from src.database.repositories.account_repo import get_account_repo

        account_repo = await get_account_repo()

        try:
            new_balance = await account_repo.debit_balance(
                session.account_id,
                amount
            )
            logger.info(
                f"Debited {amount} from account {session.account_id}, "
                f"new balance: {new_balance}"
            )
            return new_balance
        except ValueError as e:
            raise BillingError(str(e))
