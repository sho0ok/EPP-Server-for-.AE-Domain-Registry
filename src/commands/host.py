"""
Host Commands

Handles EPP host commands:
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
    ObjectNotFoundError,
    AuthorizationError,
)
from src.core.session_manager import SessionInfo
from src.core.xml_processor import EPPCommand
from src.database.repositories.host_repo import get_host_repo
from src.utils.roid_generator import generate_roid
from src.validators.epp_validator import get_validator

logger = logging.getLogger("epp.commands.host")


class HostCheckHandler(ObjectCommandHandler):
    """
    Handle host:check command.

    Checks availability of one or more hostnames.
    """

    command_name = "check"
    object_type = "host"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process host:check command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Get hostnames to check
        names = data.get("names", [])

        if not names:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="At least one hostname required"
            )

        # Check each host
        host_repo = await get_host_repo()
        results = await host_repo.check_multiple(names)

        # Build response
        result_data = self.response_builder.build_host_check_result(results)

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class HostInfoHandler(ObjectCommandHandler):
    """
    Handle host:info command.

    Returns detailed information about a host.
    """

    command_name = "info"
    object_type = "host"

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

        # Get host data
        host_repo = await get_host_repo()
        host = await host_repo.get_by_name(hostname)

        if not host:
            raise ObjectNotFoundError("host", hostname)

        # Build response
        result_data = self.response_builder.build_host_info_result(host)

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )

    async def get_roid_from_command(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> Optional[str]:
        """Extract ROID for transaction logging."""
        hostname = command.data.get("name")
        if hostname:
            host_repo = await get_host_repo()
            return await host_repo.get_roid(hostname)
        return None


class HostCreateHandler(ObjectCommandHandler):
    """
    Handle host:create command.

    Creates a new host.
    """

    command_name = "create"
    object_type = "host"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process host:create command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Validate required fields
        hostname = data.get("name")
        if not hostname:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Hostname required"
            )

        # Validate hostname format
        validator = get_validator()
        valid, error = validator.validate_host_name(hostname)
        if not valid:
            raise CommandError(2005, "Parameter value syntax error", reason=error)

        # Get IP addresses
        addresses = data.get("addrs", [])

        # Validate each IP address
        for addr in addresses:
            ip_addr = addr.get("addr")
            ip_version = addr.get("ip", "v4")
            valid, error = validator.validate_ip_address(ip_addr, ip_version)
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"IP {ip_addr}: {error}")

        # Check availability
        host_repo = await get_host_repo()
        avail, reason = await host_repo.check_available(hostname)
        if not avail:
            raise CommandError(
                2302,
                "Object exists",
                reason=f"Host {hostname} already exists"
            )

        # Check if this is a subordinate host and find parent domain
        parent_domain_roid = await host_repo.find_parent_domain_roid(hostname)

        # Subordinate hosts require at least one IP address
        if parent_domain_roid and not addresses:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Subordinate host requires at least one IP address"
            )

        # Generate ROID
        roid = await generate_roid()

        # Create host
        try:
            host = await host_repo.create(
                hostname=hostname,
                roid=roid,
                account_id=session.account_id,
                user_id=session.user_id,
                addresses=addresses,
                parent_domain_roid=parent_domain_roid
            )
        except Exception as e:
            logger.error(f"Failed to create host {hostname}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        # Build response
        result_data = self.response_builder.build_host_create_result(
            name=hostname,
            cr_date=host.get("crDate")
        )

        logger.info(f"Created host: {hostname} (ROID: {roid})")

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class HostUpdateHandler(ObjectCommandHandler):
    """
    Handle host:update command.

    Updates host IP addresses or name.
    """

    command_name = "update"
    object_type = "host"

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

        # Get host and verify authorization
        host_repo = await get_host_repo()
        host = await host_repo.get_by_name(hostname)

        if not host:
            raise ObjectNotFoundError("host", hostname)

        # Verify sponsoring registrar
        if host.get("_account_id") != session.account_id:
            raise AuthorizationError(
                "host",
                hostname,
                "Only sponsoring registrar can update host"
            )

        # Parse update data
        add_data = data.get("add", {})
        rem_data = data.get("rem", {})
        chg_data = data.get("chg", {})

        add_addresses = add_data.get("addrs", [])
        rem_addresses = rem_data.get("addrs", [])
        add_statuses = add_data.get("statuses", [])
        rem_statuses = rem_data.get("statuses", [])
        new_name = chg_data.get("name")

        # Validate IP addresses
        validator = get_validator()
        for addr in add_addresses:
            ip_addr = addr.get("addr")
            ip_version = addr.get("ip", "v4")
            valid, error = validator.validate_ip_address(ip_addr, ip_version)
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"IP {ip_addr}: {error}")

        # Validate new name if provided
        if new_name:
            valid, error = validator.validate_host_name(new_name)
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"New name: {error}")

        # Validate client can only modify client statuses
        for status in add_statuses + rem_statuses:
            if status.startswith("server"):
                raise CommandError(
                    2306,
                    "Parameter value policy error",
                    reason="Cannot modify server statuses"
                )

        # Perform update
        try:
            await host_repo.update(
                hostname=hostname,
                user_id=session.user_id,
                add_addresses=add_addresses if add_addresses else None,
                rem_addresses=rem_addresses if rem_addresses else None,
                add_statuses=add_statuses if add_statuses else None,
                rem_statuses=rem_statuses if rem_statuses else None,
                new_name=new_name
            )
        except Exception as e:
            logger.error(f"Failed to update host {hostname}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        logger.info(f"Updated host: {hostname}")

        return self.success_response(cl_trid=cl_trid)


class HostDeleteHandler(ObjectCommandHandler):
    """
    Handle host:delete command.

    Deletes a host.
    """

    command_name = "delete"
    object_type = "host"

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

        # Get host and verify authorization
        host_repo = await get_host_repo()
        host = await host_repo.get_by_name(hostname)

        if not host:
            raise ObjectNotFoundError("host", hostname)

        # Verify sponsoring registrar
        if host.get("_account_id") != session.account_id:
            raise AuthorizationError(
                "host",
                hostname,
                "Only sponsoring registrar can delete host"
            )

        # Check if host is in use
        in_use, usage = await host_repo.is_in_use(hostname)
        if in_use:
            raise CommandError(
                2305,
                "Object association prohibits operation",
                reason=usage
            )

        # Perform delete
        try:
            await host_repo.delete(hostname)
        except Exception as e:
            logger.error(f"Failed to delete host {hostname}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        logger.info(f"Deleted host: {hostname}")

        return self.success_response(cl_trid=cl_trid)

    async def get_roid_from_command(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> Optional[str]:
        """Extract ROID for transaction logging."""
        hostname = command.data.get("name")
        if hostname:
            host_repo = await get_host_repo()
            return await host_repo.get_roid(hostname)
        return None


# Handler registry
HOST_HANDLERS = {
    "check": HostCheckHandler,
    "info": HostInfoHandler,
    "create": HostCreateHandler,
    "update": HostUpdateHandler,
    "delete": HostDeleteHandler,
}


def get_host_handler(command_type: str) -> Optional[ObjectCommandHandler]:
    """
    Get handler for host command.

    Args:
        command_type: Command type (check, info, create, etc.)

    Returns:
        Handler instance or None
    """
    handler_class = HOST_HANDLERS.get(command_type)
    if handler_class:
        return handler_class()
    return None
