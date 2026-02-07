"""
Host Commands

Handles EPP host commands via ARI PL/SQL stored procedures:
- check: Check host availability
- info: Get host information
- create: Create new host
- update: Update host
- delete: Delete host
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

logger = logging.getLogger("epp.commands.host")


def _plsql_response_to_epp_error(response_code: int, response_message: str) -> CommandError:
    """Convert a PL/SQL stored procedure response to a CommandError."""
    return CommandError(
        code=response_code,
        message=response_message or "Command failed"
    )


class HostCheckHandler(ObjectCommandHandler):
    """Handle host:check command."""

    command_name = "check"
    object_type = "host"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process host:check command."""
        cl_trid = command.client_transaction_id
        data = command.data

        names = data.get("names", [])
        if not names:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="At least one hostname required"
            )

        plsql = await get_plsql_caller()
        result = await plsql.host_check(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            hostnames=names
        )

        response_code = result.get("response_code", 2400)
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        results = result.get("results", [])
        result_data = self.response_builder.build_host_check_result(results)

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class HostInfoHandler(ObjectCommandHandler):
    """Handle host:info command."""

    command_name = "info"
    object_type = "host"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process host:info command."""
        cl_trid = command.client_transaction_id
        data = command.data

        hostname = data.get("name")
        if not hostname:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Hostname required"
            )

        plsql = await get_plsql_caller()
        result = await plsql.host_info(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=hostname
        )

        response_code = result.get("response_code", 2400)
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        result_data = self.response_builder.build_host_info_result(result)

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class HostCreateHandler(ObjectCommandHandler):
    """Handle host:create command."""

    command_name = "create"
    object_type = "host"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process host:create command."""
        cl_trid = command.client_transaction_id
        data = command.data

        hostname = data.get("name")
        if not hostname:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Hostname required"
            )

        addresses = data.get("addrs", [])

        plsql = await get_plsql_caller()
        result = await plsql.host_create(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=hostname,
            addresses=addresses if addresses else None
        )

        response_code = result.get("response_code", 2400)
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        result_data = self.response_builder.build_host_create_result(
            name=result.get("cr_name", hostname),
            cr_date=result.get("cr_date")
        )

        logger.info(f"Created host via PL/SQL: {hostname}")

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class HostUpdateHandler(ObjectCommandHandler):
    """Handle host:update command."""

    command_name = "update"
    object_type = "host"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process host:update command."""
        cl_trid = command.client_transaction_id
        data = command.data

        hostname = data.get("name")
        if not hostname:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Hostname required"
            )

        add_data = data.get("add", {})
        rem_data = data.get("rem", {})
        chg_data = data.get("chg", {})

        add_addresses = add_data.get("addrs", [])
        rem_addresses = rem_data.get("addrs", [])
        add_statuses_raw = add_data.get("statuses", [])
        rem_statuses_raw = rem_data.get("statuses", [])
        new_name = chg_data.get("name")

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
        result = await plsql.host_update(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=hostname,
            add_addresses=add_addresses or None,
            rem_addresses=rem_addresses or None,
            add_statuses=add_statuses or None,
            rem_statuses=rem_statuses or None,
            new_name=new_name
        )

        response_code = result.get("response_code", 2400)
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        logger.info(f"Updated host via PL/SQL: {hostname}")

        return self.success_response(cl_trid=cl_trid)


class HostDeleteHandler(ObjectCommandHandler):
    """Handle host:delete command."""

    command_name = "delete"
    object_type = "host"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process host:delete command."""
        cl_trid = command.client_transaction_id
        data = command.data

        hostname = data.get("name")
        if not hostname:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Hostname required"
            )

        plsql = await get_plsql_caller()
        result = await plsql.host_delete(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=hostname
        )

        response_code = result.get("response_code", 2400)
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        logger.info(f"Deleted host via PL/SQL: {hostname}")

        return self.success_response(cl_trid=cl_trid)


# Handler registry
HOST_HANDLERS = {
    "check": HostCheckHandler,
    "info": HostInfoHandler,
    "create": HostCreateHandler,
    "update": HostUpdateHandler,
    "delete": HostDeleteHandler,
}


def get_host_handler(command_type: str) -> Optional[ObjectCommandHandler]:
    """Get handler for host command."""
    handler_class = HOST_HANDLERS.get(command_type)
    if handler_class:
        return handler_class()
    return None
