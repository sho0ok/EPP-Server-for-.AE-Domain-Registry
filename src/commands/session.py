"""
Session Commands

Handles EPP session commands:
- hello: Return server greeting
- login: Authenticate and establish session
- logout: End session
- poll: Message queue operations
"""

import logging
from typing import Optional

from src.commands.base import BaseCommandHandler
from src.core.session_manager import SessionInfo, get_session_manager
from src.core.xml_processor import EPPCommand

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
    Handle EPP poll command via ARI's epp.poll() stored procedure.

    Manages message queue:
    - poll op="req": Request next message
    - poll op="ack": Acknowledge message
    """

    command_name = "poll"
    requires_auth = True
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process poll command via PL/SQL."""
        cl_trid = command.client_transaction_id
        data = command.data

        op = data.get("op", "req")
        msgid = data.get("msgID")

        if op not in ("req", "ack"):
            return self.error_response(
                code=2005,
                message="Parameter value syntax error",
                cl_trid=cl_trid,
                reason=f"Invalid poll op: {op}",
                value=op
            )

        if op == "ack" and not msgid:
            return self.error_response(
                code=2003,
                message="Required parameter missing",
                cl_trid=cl_trid,
                reason="msgID is required for poll ack"
            )

        from src.database.plsql_caller import get_plsql_caller
        plsql = await get_plsql_caller()

        logger.info(
            f"Poll: conn_id={session.connection_id}, ses_id={session.session_id}, "
            f"acc_id={session.account_id}, user={session.username}, op={op}, msgid={msgid}"
        )

        result = await plsql.poll(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            op=op,
            msgid=msgid
        )

        logger.info(f"Poll result: {result}")

        response_code = result.get("response_code", 2400)

        if response_code >= 2000:
            return self.response_builder.build_error(
                code=response_code,
                message=result.get("response_message", "Command failed"),
                cl_trid=cl_trid,
                sv_trid=result.get("sv_trid")
            )

        # Build message queue info if present
        msg_queue = None
        if result.get("msgq_id") is not None:
            msg_queue = {
                "count": result.get("msgq_count", 0),
                "id": str(result["msgq_id"]),
            }
            if result.get("msgq_qdate"):
                msg_queue["qDate"] = result["msgq_qdate"]
            if result.get("msgq_msg"):
                msg_queue["msg"] = result["msgq_msg"]
            if result.get("msgq_lang"):
                msg_queue["lang"] = result["msgq_lang"]

        # Build resdata if present
        result_data = None
        resdata_type = result.get("resdata_type")

        if resdata_type == "domain_trndata" and result.get("dom_trn_status"):
            result_data = self.response_builder.build_domain_transfer_result(
                name=result["dom_trn_name"],
                tr_status=result["dom_trn_status"],
                re_id=result.get("dom_trn_reid", ""),
                re_date=result.get("dom_trn_redate", ""),
                ac_id=result.get("dom_trn_acid", ""),
                ac_date=result.get("dom_trn_acdate", ""),
                ex_date=result.get("dom_trn_exdate")
            )
        elif resdata_type == "contact_trndata" and result.get("con_trn_status"):
            result_data = self.response_builder.build_contact_transfer_result(
                contact_id=result["con_trn_id"],
                tr_status=result["con_trn_status"],
                re_id=result.get("con_trn_reid", ""),
                re_date=result.get("con_trn_redate", ""),
                ac_id=result.get("con_trn_acid", ""),
                ac_date=result.get("con_trn_acdate", "")
            )
        elif resdata_type == "domain_pandata" and result.get("dom_pan_name"):
            result_data = self.response_builder.build_domain_pandata_result(
                name=result["dom_pan_name"],
                pa_result=result.get("dom_pan_result") == "1",
                pa_trid_cl=result.get("dom_pan_trid_cl"),
                pa_trid_sv=result.get("dom_pan_trid_sv"),
                pa_date=result.get("dom_pan_date", "")
            )

        return self.response_builder.build_response(
            code=response_code,
            message=result.get("response_message"),
            cl_trid=cl_trid,
            sv_trid=result.get("sv_trid"),
            result_data=result_data,
            msg_queue=msg_queue
        )


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
