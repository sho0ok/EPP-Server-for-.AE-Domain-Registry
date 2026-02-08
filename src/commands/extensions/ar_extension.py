"""
AR Extension Commands

Handles AusRegistry-specific EPP extension commands per arext-1.0 schema:
- ArUndelete: Restore a deleted domain from redemption grace period
- ArUnrenew: Cancel a pending renewal and revert expiry date
- ArPolicyDelete: Delete domain for policy violation
- ArPolicyUndelete: Restore domain deleted for policy violation

All commands delegate to epp_arext.* PL/SQL stored procedures which handle
authorization, status validation, billing, audit logging, and transaction recording.

Namespace: urn:X-ar:params:xml:ns:arext-1.0
"""

import logging
from datetime import datetime
from typing import Optional

from src.commands.base import (
    ObjectCommandHandler,
    CommandError,
)
from src.core.session_manager import SessionInfo
from src.core.xml_processor import EPPCommand
from src.database.plsql_caller import get_plsql_caller

logger = logging.getLogger("epp.commands.ar_extension")

# AR Extension namespace
AREXT_NS = "urn:X-ar:params:xml:ns:arext-1.0"


class ArUndeleteHandler(ObjectCommandHandler):
    """
    Handle arext:command/undelete command via epp_arext.domain_undelete().

    Restores a domain from pending delete / redemption grace period.
    PL/SQL handles all validation, authorization, billing, and audit.
    """

    command_name = "ar_undelete"
    object_type = "domain"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AR undelete command."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        plsql = await get_plsql_caller()
        result = await plsql.domain_undelete(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=domain_name
        )

        rc = result.get("response_code", 2400)
        if rc >= 2000:
            return self.response_builder.build_error(
                code=rc,
                message=result.get("response_message", "Command failed"),
                cl_trid=cl_trid,
                sv_trid=result.get("sv_trid")
            )

        result_data = self.response_builder.build_ar_undelete_result(
            name=domain_name
        )

        logger.info(f"Undeleted domain: {domain_name}")

        return self.response_builder.build_response(
            code=rc,
            message=result.get("response_message"),
            cl_trid=cl_trid,
            sv_trid=result.get("sv_trid"),
            result_data=result_data
        )


class ArUnrenewHandler(ObjectCommandHandler):
    """
    Handle arext:command/unrenew command via epp_arext.domain_unrenew().

    Cancels a pending renewal and reverts the domain to its previous expiry date.
    PL/SQL handles all validation, authorization, billing refund, and audit.
    """

    command_name = "ar_unrenew"
    object_type = "domain"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AR unrenew command."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        cur_exp_date = data.get("curExpDate")
        if not cur_exp_date:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="curExpDate required for unrenew"
            )

        # Parse date string to datetime if needed
        if isinstance(cur_exp_date, str):
            try:
                cur_exp_date = datetime.strptime(cur_exp_date[:10], "%Y-%m-%d")
            except ValueError:
                raise CommandError(
                    2005,
                    "Parameter value syntax error",
                    reason="Invalid curExpDate format"
                )

        plsql = await get_plsql_caller()
        result = await plsql.domain_unrenew(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=domain_name,
            cur_exp_date=cur_exp_date
        )

        rc = result.get("response_code", 2400)
        if rc >= 2000:
            return self.response_builder.build_error(
                code=rc,
                message=result.get("response_message", "Command failed"),
                cl_trid=cl_trid,
                sv_trid=result.get("sv_trid")
            )

        result_data = self.response_builder.build_ar_unrenew_result(
            name=result.get("name", domain_name),
            ex_date=result.get("ex_date")
        )

        logger.info(f"Unrenewed domain: {domain_name}")

        return self.response_builder.build_response(
            code=rc,
            message=result.get("response_message"),
            cl_trid=cl_trid,
            sv_trid=result.get("sv_trid"),
            result_data=result_data
        )


class ArPolicyDeleteHandler(ObjectCommandHandler):
    """
    Handle arext:command/policyDelete command via epp_arext.domain_policy_delete().

    Deletes domain for policy violation. Registry-initiated operation.
    PL/SQL handles all validation, authorization, and audit.
    """

    command_name = "ar_policy_delete"
    object_type = "domain"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AR policy delete command."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        reason = data.get("reason")

        plsql = await get_plsql_caller()
        result = await plsql.domain_policy_delete(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=domain_name,
            reason=reason
        )

        rc = result.get("response_code", 2400)
        if rc >= 2000:
            return self.response_builder.build_error(
                code=rc,
                message=result.get("response_message", "Command failed"),
                cl_trid=cl_trid,
                sv_trid=result.get("sv_trid")
            )

        logger.info(f"Policy deleted domain: {domain_name} (reason: {reason})")

        return self.response_builder.build_response(
            code=rc,
            message=result.get("response_message"),
            cl_trid=cl_trid,
            sv_trid=result.get("sv_trid")
        )


class ArPolicyUndeleteHandler(ObjectCommandHandler):
    """
    Handle arext:command/policyUndelete command via epp_arext.domain_policy_undelete().

    Restores a domain that was deleted due to policy violation.
    PL/SQL handles all validation, authorization, and audit.
    """

    command_name = "ar_policy_undelete"
    object_type = "domain"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AR policy undelete command."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        plsql = await get_plsql_caller()
        result = await plsql.domain_policy_undelete(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=domain_name
        )

        rc = result.get("response_code", 2400)
        if rc >= 2000:
            return self.response_builder.build_error(
                code=rc,
                message=result.get("response_message", "Command failed"),
                cl_trid=cl_trid,
                sv_trid=result.get("sv_trid")
            )

        result_data = self.response_builder.build_ar_undelete_result(
            name=domain_name
        )

        logger.info(f"Policy undeleted domain: {domain_name}")

        return self.response_builder.build_response(
            code=rc,
            message=result.get("response_message"),
            cl_trid=cl_trid,
            sv_trid=result.get("sv_trid"),
            result_data=result_data
        )


# Handler registry for AR extension commands
AR_EXTENSION_HANDLERS = {
    "ar_undelete": ArUndeleteHandler,
    "ar_unrenew": ArUnrenewHandler,
    "ar_policy_delete": ArPolicyDeleteHandler,
    "ar_policy_undelete": ArPolicyUndeleteHandler,
}


def get_ar_extension_handler(command_type: str) -> Optional[ObjectCommandHandler]:
    """
    Get handler for AR extension command.

    Args:
        command_type: Command type (ar_undelete, ar_unrenew, etc.)

    Returns:
        Handler instance or None
    """
    handler_class = AR_EXTENSION_HANDLERS.get(command_type)
    if handler_class:
        return handler_class()
    return None
