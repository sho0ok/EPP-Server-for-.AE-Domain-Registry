"""
Contact Commands

Handles EPP contact commands via ARI PL/SQL stored procedures:
- check: Check contact availability
- info: Get contact information
- create: Create new contact
- update: Update contact
- delete: Delete contact
- transfer: Transfer contact
"""

import logging
from typing import Any, Dict, List, Optional

from src.commands.base import (
    ObjectCommandHandler,
    CommandError,
)
from src.core.session_manager import SessionInfo
from src.core.xml_processor import EPPCommand
from src.database.plsql_caller import get_plsql_caller
from src.utils.password_utils import generate_auth_info, validate_auth_info
from src.validators.epp_validator import get_validator

logger = logging.getLogger("epp.commands.contact")


def _plsql_response_to_epp_error(response_code: int, response_message: str) -> CommandError:
    """Convert a PL/SQL stored procedure response to a CommandError."""
    return CommandError(
        code=response_code,
        message=response_message or "Command failed"
    )


class ContactCheckHandler(ObjectCommandHandler):
    """Handle contact:check command."""

    command_name = "check"
    object_type = "contact"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process contact:check command."""
        cl_trid = command.client_transaction_id
        data = command.data

        ids = data.get("ids", [])
        if not ids:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="At least one contact ID required"
            )

        plsql = await get_plsql_caller()
        result = await plsql.contact_check(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            contact_ids=ids
        )

        response_code = result.get("response_code", 2400)
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        results = result.get("results", [])
        result_data = self.response_builder.build_contact_check_result(results)

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class ContactInfoHandler(ObjectCommandHandler):
    """Handle contact:info command."""

    command_name = "info"
    object_type = "contact"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process contact:info command."""
        cl_trid = command.client_transaction_id
        data = command.data

        contact_id = data.get("id")
        if not contact_id:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Contact ID required"
            )

        auth_info = data.get("authInfo")

        plsql = await get_plsql_caller()
        result = await plsql.contact_info(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            contact_id=contact_id,
            auth_info=auth_info
        )

        response_code = result.get("response_code", 2400)
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        result_data = self.response_builder.build_contact_info_result(result)

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class ContactCreateHandler(ObjectCommandHandler):
    """Handle contact:create command."""

    command_name = "create"
    object_type = "contact"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process contact:create command."""
        cl_trid = command.client_transaction_id
        data = command.data

        contact_id = data.get("id")
        if not contact_id:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Contact ID required"
            )

        # Client-side format validation
        validator = get_validator()
        valid, error = validator.validate_contact_id(contact_id)
        if not valid:
            raise CommandError(2005, "Parameter value syntax error", reason=error)

        email = data.get("email")
        if not email:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Email required"
            )
        valid, error = validator.validate_email(email)
        if not valid:
            raise CommandError(2005, "Parameter value syntax error", reason=error)

        postal_int = data.get("postalInfo_int")
        postal_loc = data.get("postalInfo_loc")
        if not postal_int and not postal_loc:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="At least one postalInfo required"
            )

        voice = data.get("voice")
        if voice:
            valid, error = validator.validate_phone(voice, data.get("voice_ext"))
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"Voice: {error}")

        fax = data.get("fax")
        if fax:
            valid, error = validator.validate_phone(fax, data.get("fax_ext"))
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"Fax: {error}")

        # Handle auth info
        auth_info = data.get("authInfo")
        if auth_info:
            valid, error = validate_auth_info(auth_info)
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"AuthInfo: {error}")
        else:
            auth_info = generate_auth_info()

        plsql = await get_plsql_caller()
        result = await plsql.contact_create(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            contact_id=contact_id,
            postalinfo_int=postal_int,
            postalinfo_loc=postal_loc,
            voice=voice,
            voice_ext=data.get("voice_ext"),
            fax=fax,
            fax_ext=data.get("fax_ext"),
            email=email,
            auth_info=auth_info
        )

        response_code = result.get("response_code", 2400)
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        result_data = self.response_builder.build_contact_create_result(
            contact_id=result.get("cr_id", contact_id),
            cr_date=result.get("cr_date")
        )

        logger.info(f"Created contact via PL/SQL: {contact_id}")

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class ContactUpdateHandler(ObjectCommandHandler):
    """Handle contact:update command."""

    command_name = "update"
    object_type = "contact"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process contact:update command."""
        cl_trid = command.client_transaction_id
        data = command.data

        contact_id = data.get("id")
        if not contact_id:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Contact ID required"
            )

        # Client-side format validation
        validator = get_validator()
        chg_data = data.get("chg", {})

        if chg_data.get("email"):
            valid, error = validator.validate_email(chg_data["email"])
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"Email: {error}")

        if chg_data.get("voice"):
            valid, error = validator.validate_phone(chg_data["voice"], chg_data.get("voice_ext"))
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"Voice: {error}")

        if chg_data.get("fax"):
            valid, error = validator.validate_phone(chg_data["fax"], chg_data.get("fax_ext"))
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"Fax: {error}")

        if chg_data.get("authInfo"):
            valid, error = validate_auth_info(chg_data["authInfo"])
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"AuthInfo: {error}")

        # Extract add/rem statuses
        add_data = data.get("add", {})
        rem_data = data.get("rem", {})

        add_statuses_raw = add_data.get("statuses", [])
        rem_statuses_raw = rem_data.get("statuses", [])

        # Normalize statuses to dict format
        add_statuses = []
        for s in add_statuses_raw:
            if isinstance(s, dict) and s.get("s"):
                add_statuses.append(s)
            elif isinstance(s, str) and s:
                add_statuses.append({"s": s, "lang": None, "reason": None})

        rem_statuses = []
        for s in rem_statuses_raw:
            if isinstance(s, dict) and s.get("s"):
                rem_statuses.append(s)
            elif isinstance(s, str) and s:
                rem_statuses.append({"s": s, "lang": None, "reason": None})

        plsql = await get_plsql_caller()
        result = await plsql.contact_update(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            contact_id=contact_id,
            add_statuses=add_statuses or None,
            rem_statuses=rem_statuses or None,
            chg_postalinfo_int=chg_data.get("postalInfo_int"),
            chg_postalinfo_loc=chg_data.get("postalInfo_loc"),
            chg_voice=chg_data.get("voice"),
            chg_voice_ext=chg_data.get("voice_ext"),
            chg_fax=chg_data.get("fax"),
            chg_fax_ext=chg_data.get("fax_ext"),
            chg_email=chg_data.get("email"),
            chg_authinfo=chg_data.get("authInfo")
        )

        response_code = result.get("response_code", 2400)
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        logger.info(f"Updated contact via PL/SQL: {contact_id}")

        return self.success_response(cl_trid=cl_trid)


class ContactDeleteHandler(ObjectCommandHandler):
    """Handle contact:delete command."""

    command_name = "delete"
    object_type = "contact"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process contact:delete command."""
        cl_trid = command.client_transaction_id
        data = command.data

        contact_id = data.get("id")
        if not contact_id:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Contact ID required"
            )

        plsql = await get_plsql_caller()
        result = await plsql.contact_delete(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            contact_id=contact_id
        )

        response_code = result.get("response_code", 2400)
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        logger.info(f"Deleted contact via PL/SQL: {contact_id}")

        return self.success_response(cl_trid=cl_trid)


class ContactTransferHandler(ObjectCommandHandler):
    """Handle contact:transfer command."""

    command_name = "transfer"
    object_type = "contact"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process contact:transfer command."""
        cl_trid = command.client_transaction_id
        data = command.data

        contact_id = data.get("id")
        if not contact_id:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Contact ID required"
            )

        op = data.get("op", "request")
        if op not in ("request", "approve", "reject", "cancel", "query"):
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid transfer operation: {op}"
            )

        auth_info = data.get("authInfo")

        plsql = await get_plsql_caller()
        result = await plsql.contact_transfer(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            op=op,
            contact_id=contact_id,
            auth_info=auth_info
        )

        response_code = result.get("response_code", 2400)
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        # Build transfer result data if present
        if result.get("trStatus"):
            result_data = self.response_builder.build_contact_transfer_result(
                contact_id=result.get("id", contact_id),
                tr_status=result.get("trStatus"),
                re_id=result.get("reID"),
                re_date=result.get("reDate"),
                ac_id=result.get("acID"),
                ac_date=result.get("acDate")
            )
        else:
            result_data = None

        logger.info(f"Contact transfer ({op}) via PL/SQL: {contact_id}")

        return self.success_response(
            cl_trid=cl_trid,
            code=response_code,
            message=result.get("response_message"),
            result_data=result_data
        )


# Handler registry
CONTACT_HANDLERS = {
    "check": ContactCheckHandler,
    "info": ContactInfoHandler,
    "create": ContactCreateHandler,
    "update": ContactUpdateHandler,
    "delete": ContactDeleteHandler,
    "transfer": ContactTransferHandler,
}


def get_contact_handler(command_type: str) -> Optional[ObjectCommandHandler]:
    """Get handler for contact command."""
    handler_class = CONTACT_HANDLERS.get(command_type)
    if handler_class:
        return handler_class()
    return None
