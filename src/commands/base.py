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

            return response

        except CommandError as e:
            response_code = e.code
            logger.warning(
                f"Command {self.command_name} failed: [{e.code}] {e.message}"
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
    """

    # Object type (domain, contact, host)
    object_type: str = "unknown"

    async def execute(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """
        Execute with object-specific logging.

        Extracts ROID for transaction logging when available.
        """
        cl_trid = command.client_transaction_id
        start_time = datetime.utcnow()
        trn_id = None
        response_code = 2400
        roid = None

        try:
            if self.requires_auth and not session.authenticated:
                raise AuthenticationError("Command use error: not logged in")

            session_mgr = get_session_manager()

            # Try to get ROID from command data
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

            return response

        except CommandError as e:
            response_code = e.code
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
            response_code = 2400
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
                    await session_mgr.complete_command(
                        trn_id=trn_id,
                        response_code=response_code,
                        start_time=start_time
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
