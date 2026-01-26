"""
Session Commands

Handles EPP session commands:
- hello: Return server greeting
- login: Authenticate and establish session
- logout: End session
- poll: Message queue operations
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.commands.base import BaseCommandHandler, CommandError
from src.core.session_manager import SessionInfo, get_session_manager
from src.core.xml_processor import EPPCommand
from src.utils.response_builder import get_response_builder

logger = logging.getLogger("epp.commands.session")


class HelloHandler(BaseCommandHandler):
    """
    Handle EPP hello command.

    Returns server greeting with capabilities.
    No authentication required.
    """

    command_name = "hello"
    requires_auth = False

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Return server greeting."""
        return self.response_builder.build_greeting()


class LoginHandler(BaseCommandHandler):
    """
    Handle EPP login command.

    Authenticates user and establishes session.
    No prior authentication required.
    """

    command_name = "login"
    requires_auth = False

    # Maximum login failures before closing connection
    MAX_LOGIN_FAILURES = 3

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process login command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Already logged in?
        if session.authenticated:
            return self.error_response(
                code=2002,
                message="Command use error: already logged in",
                cl_trid=cl_trid
            )

        # Extract credentials
        client_id = data.get("clID")
        password = data.get("pw")
        new_password = data.get("newPW")
        version = data.get("version", "1.0")
        lang = data.get("lang", "en")
        object_uris = data.get("objURIs", [])
        extension_uris = data.get("extURIs", [])

        # Validate required parameters
        if not client_id:
            return self.error_response(
                code=2003,
                message="Required parameter missing",
                cl_trid=cl_trid,
                reason="clID is required"
            )

        if not password:
            return self.error_response(
                code=2003,
                message="Required parameter missing",
                cl_trid=cl_trid,
                reason="pw is required"
            )

        # Validate version
        if version not in self.response_builder.supported_versions:
            return self.error_response(
                code=2100,
                message="Unimplemented protocol version",
                cl_trid=cl_trid,
                value=version
            )

        # Validate language
        if lang not in self.response_builder.supported_languages:
            return self.error_response(
                code=2102,
                message="Unimplemented option",
                cl_trid=cl_trid,
                reason=f"Language '{lang}' not supported"
            )

        # Validate object URIs
        for uri in object_uris:
            if uri not in self.response_builder.supported_objects:
                return self.error_response(
                    code=2307,
                    message="Unimplemented object service",
                    cl_trid=cl_trid,
                    value=uri
                )

        # Authenticate
        session_mgr = get_session_manager()
        result = await session_mgr.authenticate(
            session=session,
            username=client_id,
            password=password,
            version=version,
            language=lang,
            object_uris=object_uris,
            extension_uris=extension_uris
        )

        if not result["success"]:
            # Check if we should close connection
            if session.login_failures >= self.MAX_LOGIN_FAILURES:
                return self.error_response(
                    code=2501,
                    message="Authentication error; server closing connection",
                    cl_trid=cl_trid
                )

            return self.error_response(
                code=result["code"],
                message=result["message"],
                cl_trid=cl_trid
            )

        # Handle password change if requested
        if new_password:
            await self._change_password(session, new_password)
            logger.info(f"Password changed for user {client_id}")

        logger.info(
            f"Login successful: {client_id} from {session.client_ip}"
        )

        return self.success_response(cl_trid=cl_trid)

    async def _change_password(
        self,
        session: SessionInfo,
        new_password: str
    ) -> None:
        """Change user password."""
        from src.database.repositories.account_repo import get_account_repo

        account_repo = await get_account_repo()
        await account_repo.change_password(session.user_id, session.username, new_password)


class LogoutHandler(BaseCommandHandler):
    """
    Handle EPP logout command.

    Ends session gracefully.
    """

    command_name = "logout"
    requires_auth = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process logout command."""
        cl_trid = command.client_transaction_id

        # End session
        session_mgr = get_session_manager()
        await session_mgr.logout(session, reason="Normal logout")

        logger.info(f"Logout: {session.username} from {session.client_ip}")

        return self.response_builder.build_response(
            code=1500,
            message="Command completed successfully; ending session",
            cl_trid=cl_trid
        )


class PollHandler(BaseCommandHandler):
    """
    Handle EPP poll command.

    Manages message queue:
    - poll op="req": Request next message
    - poll op="ack": Acknowledge message
    """

    command_name = "poll"
    requires_auth = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process poll command."""
        cl_trid = command.client_transaction_id
        data = command.data

        op = data.get("op", "req")

        if op == "req":
            return await self._handle_poll_req(session, cl_trid)
        elif op == "ack":
            msg_id = data.get("msgID")
            return await self._handle_poll_ack(session, cl_trid, msg_id)
        else:
            return self.error_response(
                code=2005,
                message="Parameter value syntax error",
                cl_trid=cl_trid,
                reason=f"Invalid poll op: {op}",
                value=op
            )

    async def _handle_poll_req(
        self,
        session: SessionInfo,
        cl_trid: Optional[str]
    ) -> bytes:
        """
        Handle poll request - get next message.

        TODO: Implement actual message queue from database.
        For now, returns no messages.
        """
        # Query for pending messages
        messages = await self._get_pending_messages(session)

        if not messages:
            return self.response_builder.build_response(
                code=1300,
                message="Command completed successfully; no messages",
                cl_trid=cl_trid
            )

        # Return first message
        msg = messages[0]
        msg_queue = {
            "count": len(messages),
            "id": str(msg["id"]),
            "qDate": msg["date"],
            "msg": msg["message"]
        }

        return self.response_builder.build_response(
            code=1301,
            message="Command completed successfully; ack to dequeue",
            cl_trid=cl_trid,
            msg_queue=msg_queue
        )

    async def _handle_poll_ack(
        self,
        session: SessionInfo,
        cl_trid: Optional[str],
        msg_id: Optional[str]
    ) -> bytes:
        """
        Handle poll acknowledgment - remove message from queue.

        TODO: Implement actual message acknowledgment.
        """
        if not msg_id:
            return self.error_response(
                code=2003,
                message="Required parameter missing",
                cl_trid=cl_trid,
                reason="msgID is required for poll ack"
            )

        # Acknowledge message
        success = await self._acknowledge_message(session, msg_id)

        if not success:
            return self.error_response(
                code=2303,
                message="Object does not exist",
                cl_trid=cl_trid,
                reason=f"Message {msg_id} not found"
            )

        # Get remaining count
        remaining = await self._get_message_count(session)

        msg_queue = {
            "count": remaining,
            "id": msg_id
        }

        return self.response_builder.build_response(
            code=1000,
            message="Command completed successfully",
            cl_trid=cl_trid,
            msg_queue=msg_queue
        )

    async def _get_pending_messages(
        self,
        session: SessionInfo
    ) -> List[Dict[str, Any]]:
        """
        Get pending messages for account.

        TODO: Implement actual message retrieval from database.
        """
        # Placeholder - no message queue implemented yet
        return []

    async def _acknowledge_message(
        self,
        session: SessionInfo,
        msg_id: str
    ) -> bool:
        """
        Acknowledge and remove message from queue.

        TODO: Implement actual message acknowledgment.
        """
        # Placeholder
        return True

    async def _get_message_count(
        self,
        session: SessionInfo
    ) -> int:
        """
        Get count of remaining messages.

        TODO: Implement actual count query.
        """
        return 0


# Handler registry
SESSION_HANDLERS = {
    "hello": HelloHandler,
    "login": LoginHandler,
    "logout": LogoutHandler,
    "poll": PollHandler,
}


def get_session_handler(command_type: str) -> Optional[BaseCommandHandler]:
    """
    Get handler for session command.

    Args:
        command_type: Command type (hello, login, logout, poll)

    Returns:
        Handler instance or None
    """
    handler_class = SESSION_HANDLERS.get(command_type)
    if handler_class:
        return handler_class()
    return None
