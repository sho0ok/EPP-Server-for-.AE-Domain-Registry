"""
Domain Commands

Handles EPP domain commands:
- check: Check domain availability
- info: Get domain information
- create: Register new domain
- update: Update domain
- delete: Delete domain
- renew: Renew domain
- transfer: Transfer domain
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.commands.base import (
    ObjectCommandHandler,
    CommandError,
    ObjectNotFoundError,
    AuthorizationError,
)
from src.core.session_manager import SessionInfo
from src.core.xml_processor import EPPCommand
from src.database.repositories.domain_repo import get_domain_repo
from src.database.repositories.account_repo import get_account_repo
from src.utils.roid_generator import generate_roid
from src.utils.password_utils import generate_auth_info, validate_auth_info
from src.validators.epp_validator import get_validator

logger = logging.getLogger("epp.commands.domain")


class DomainCheckHandler(ObjectCommandHandler):
    """
    Handle domain:check command.

    Checks availability of one or more domain names.
    """

    command_name = "check"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:check command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Get domain names to check
        names = data.get("names", [])

        if not names:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="At least one domain name required"
            )

        # Check each domain
        domain_repo = await get_domain_repo()
        results = await domain_repo.check_multiple(names)

        # Build response
        result_data = self.response_builder.build_domain_check_result(results)

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class DomainInfoHandler(ObjectCommandHandler):
    """
    Handle domain:info command.

    Returns detailed information about a domain.
    """

    command_name = "info"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:info command."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        auth_info = data.get("authInfo")
        hosts_filter = data.get("hosts", "all")  # all, del, sub, none

        # Get domain data
        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        # Check authorization for auth info
        include_auth = False
        sponsoring_account = domain.get("_account_id")

        if session.account_id == sponsoring_account:
            # Sponsoring registrar can see auth info
            include_auth = True
        elif auth_info:
            # Non-sponsor provided auth info - verify it
            if await domain_repo.verify_auth_info(domain_name, auth_info):
                include_auth = True

        # Reload with auth info if authorized
        if include_auth:
            domain = await domain_repo.get_by_name(domain_name, include_auth=True)

        # Filter hosts based on request
        if hosts_filter == "none":
            domain["nameservers"] = []
            domain["hosts"] = []
        elif hosts_filter == "del":
            # Only delegated nameservers
            domain["hosts"] = []
        elif hosts_filter == "sub":
            # Only subordinate hosts
            domain["nameservers"] = []

        # Build response
        result_data = self.response_builder.build_domain_info_result(domain)

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
        domain_name = command.data.get("name")
        if domain_name:
            domain_repo = await get_domain_repo()
            domain = await domain_repo.get_by_name(domain_name)
            if domain:
                return domain.get("roid")
        return None


class DomainCreateHandler(ObjectCommandHandler):
    """
    Handle domain:create command.

    Creates a new domain registration.
    """

    command_name = "create"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:create command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Validate required fields
        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        # Validate domain name format
        validator = get_validator()
        valid, error = validator.validate_domain_name(domain_name)
        if not valid:
            raise CommandError(2005, "Parameter value syntax error", reason=error)

        # Validate registrant
        registrant_id = data.get("registrant")
        if not registrant_id:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Registrant contact required"
            )

        # Validate period
        period = data.get("period", 1)
        unit = data.get("unit", "y")
        valid, error = validator.validate_period(period, unit)
        if not valid:
            raise CommandError(2005, "Parameter value syntax error", reason=error)

        # Get domain repo
        domain_repo = await get_domain_repo()

        # Check availability
        avail, reason = await domain_repo.check_available(domain_name)
        if not avail:
            raise CommandError(
                2302,
                "Object exists",
                reason=f"Domain {domain_name} not available: {reason}"
            )

        # Get zone configuration
        zone = domain_repo.extract_zone(domain_name)
        zone_config = await domain_repo.get_zone(zone)
        if not zone_config:
            raise CommandError(
                2306,
                "Parameter value policy error",
                reason=f"Zone {zone} not supported"
            )

        # Check zone status
        if zone_config.get("ZON_STATUS") != "ACTIVE":
            raise CommandError(
                2306,
                "Parameter value policy error",
                reason=f"Zone {zone} is not active"
            )

        # Get rate for billing
        rate = await domain_repo.get_rate(zone, period, unit)
        if rate is None:
            raise CommandError(
                2306,
                "Parameter value policy error",
                reason=f"No rate found for {period}{unit} in zone {zone}"
            )

        # Check account balance
        account_repo = await get_account_repo()
        balance = await account_repo.get_balance(session.account_id)
        if balance < rate:
            raise CommandError(
                2104,
                "Billing failure",
                reason="Insufficient balance"
            )

        # Generate ROID
        roid = await generate_roid()

        # Handle auth info
        auth_info = data.get("authInfo")
        if auth_info:
            valid, error = validate_auth_info(auth_info)
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"AuthInfo: {error}")
        else:
            auth_info = generate_auth_info()

        # Get contacts and nameservers
        contacts = data.get("contacts", [])
        nameservers = data.get("ns", [])

        # Create domain
        try:
            domain = await domain_repo.create(
                domain_name=domain_name,
                roid=roid,
                account_id=session.account_id,
                user_id=session.user_id,
                registrant_id=registrant_id,
                auth_info=auth_info,
                period=period,
                unit=unit,
                contacts=contacts,
                nameservers=nameservers
            )

            # Debit account
            await account_repo.debit(session.account_id, rate, f"Domain create: {domain_name}")

        except Exception as e:
            logger.error(f"Failed to create domain {domain_name}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        # Build response
        result_data = self.response_builder.build_domain_create_result(
            name=domain_name,
            cr_date=domain.get("crDate"),
            ex_date=domain.get("exDate")
        )

        logger.info(f"Created domain: {domain_name} (ROID: {roid})")

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class DomainUpdateHandler(ObjectCommandHandler):
    """
    Handle domain:update command.

    Updates domain contacts, nameservers, or statuses.
    """

    command_name = "update"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:update command."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        # Get domain and verify authorization
        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        # Verify sponsoring registrar
        if domain.get("_account_id") != session.account_id:
            raise AuthorizationError(
                "domain",
                domain_name,
                "Only sponsoring registrar can update domain"
            )

        # Parse update data
        add_data = data.get("add", {})
        rem_data = data.get("rem", {})
        chg_data = data.get("chg", {})

        add_contacts = add_data.get("contacts", [])
        rem_contacts = rem_data.get("contacts", [])
        add_nameservers = add_data.get("ns", [])
        rem_nameservers = rem_data.get("ns", [])
        add_statuses = add_data.get("statuses", [])
        rem_statuses = rem_data.get("statuses", [])

        registrant_id = chg_data.get("registrant")
        auth_info = chg_data.get("authInfo")

        # Validate auth info if being changed
        if auth_info:
            valid, error = validate_auth_info(auth_info)
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"AuthInfo: {error}")

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
            await domain_repo.update(
                domain_name=domain_name,
                user_id=session.user_id,
                registrant_id=registrant_id,
                auth_info=auth_info,
                add_contacts=add_contacts if add_contacts else None,
                rem_contacts=rem_contacts if rem_contacts else None,
                add_nameservers=add_nameservers if add_nameservers else None,
                rem_nameservers=rem_nameservers if rem_nameservers else None,
                add_statuses=add_statuses if add_statuses else None,
                rem_statuses=rem_statuses if rem_statuses else None
            )
        except Exception as e:
            logger.error(f"Failed to update domain {domain_name}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        logger.info(f"Updated domain: {domain_name}")

        return self.success_response(cl_trid=cl_trid)


class DomainDeleteHandler(ObjectCommandHandler):
    """
    Handle domain:delete command.

    Deletes a domain (marks as pendingDelete).
    """

    command_name = "delete"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:delete command."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        # Get domain and verify authorization
        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        # Verify sponsoring registrar
        if domain.get("_account_id") != session.account_id:
            raise AuthorizationError(
                "domain",
                domain_name,
                "Only sponsoring registrar can delete domain"
            )

        # Perform delete (marks as pendingDelete)
        try:
            await domain_repo.delete(domain_name, immediate=False)
        except Exception as e:
            logger.error(f"Failed to delete domain {domain_name}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        logger.info(f"Marked domain for deletion: {domain_name}")

        # Return 1001 for pending action
        return self.success_response(
            cl_trid=cl_trid,
            code=1001,
            msg="Command completed successfully; action pending"
        )

    async def get_roid_from_command(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> Optional[str]:
        """Extract ROID for transaction logging."""
        domain_name = command.data.get("name")
        if domain_name:
            domain_repo = await get_domain_repo()
            return await domain_repo.get_roid(domain_name)
        return None


class DomainRenewHandler(ObjectCommandHandler):
    """
    Handle domain:renew command.

    Renews a domain registration.
    """

    command_name = "renew"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:renew command."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        # Current expiry date is required
        cur_exp_date_str = data.get("curExpDate")
        if not cur_exp_date_str:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Current expiration date required"
            )

        # Parse expiry date
        try:
            if "T" in cur_exp_date_str:
                current_expiry = datetime.fromisoformat(cur_exp_date_str.replace("Z", "+00:00"))
            else:
                current_expiry = datetime.strptime(cur_exp_date_str, "%Y-%m-%d")
        except ValueError:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason="Invalid date format for curExpDate"
            )

        # Get domain and verify authorization
        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        # Verify sponsoring registrar
        if domain.get("_account_id") != session.account_id:
            raise AuthorizationError(
                "domain",
                domain_name,
                "Only sponsoring registrar can renew domain"
            )

        # Get period (optional, default 1 year)
        period = data.get("period", 1)
        unit = data.get("unit", "y")

        # Validate period
        validator = get_validator()
        valid, error = validator.validate_period(period, unit)
        if not valid:
            raise CommandError(2005, "Parameter value syntax error", reason=error)

        # Get zone and rate
        zone = domain.get("_zone")
        rate = await domain_repo.get_rate(zone, period, unit)
        if rate is None:
            raise CommandError(
                2306,
                "Parameter value policy error",
                reason=f"No rate found for {period}{unit} in zone {zone}"
            )

        # Check account balance
        account_repo = await get_account_repo()
        balance = await account_repo.get_balance(session.account_id)
        if balance < rate:
            raise CommandError(
                2104,
                "Billing failure",
                reason="Insufficient balance"
            )

        # Perform renewal
        try:
            result = await domain_repo.renew(
                domain_name=domain_name,
                user_id=session.user_id,
                current_expiry=current_expiry,
                period=period,
                unit=unit
            )

            # Debit account
            await account_repo.debit(session.account_id, rate, f"Domain renew: {domain_name}")

        except Exception as e:
            logger.error(f"Failed to renew domain {domain_name}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        # Build response
        result_data = self.response_builder.build_domain_renew_result(
            name=domain_name,
            ex_date=result.get("exDate")
        )

        logger.info(f"Renewed domain: {domain_name}")

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class DomainTransferHandler(ObjectCommandHandler):
    """
    Handle domain:transfer command.

    Handles transfer request, approve, reject, cancel, query.
    """

    command_name = "transfer"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:transfer command."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        # Get operation type
        op = data.get("op", "request")
        if op not in ("request", "approve", "reject", "cancel", "query"):
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid transfer operation: {op}"
            )

        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        sponsoring_account = domain.get("_account_id")

        if op == "query":
            # Query transfer status
            transfer = await domain_repo.get_transfer_info(domain_name)
            if not transfer:
                raise CommandError(
                    2303,
                    "Object does not exist",
                    reason="No pending transfer for domain"
                )

            result_data = self.response_builder.build_domain_transfer_result(
                name=domain_name,
                tr_status=transfer.get("TRX_STATUS"),
                re_id=transfer.get("RE_ID"),
                re_date=transfer.get("TRX_REQUEST_DATE"),
                ac_id=transfer.get("AC_ID"),
                ac_date=transfer.get("TRX_ACCEPT_DATE"),
                ex_date=domain.get("exDate")
            )

            return self.success_response(
                cl_trid=cl_trid,
                result_data=result_data
            )

        elif op == "request":
            # Request transfer
            auth_info = data.get("authInfo")
            if not auth_info:
                raise CommandError(
                    2003,
                    "Required parameter missing",
                    reason="Auth info required for transfer request"
                )

            # Cannot transfer own domain
            if sponsoring_account == session.account_id:
                raise CommandError(
                    2306,
                    "Parameter value policy error",
                    reason="Cannot transfer domain you already sponsor"
                )

            period = data.get("period", 1)
            unit = data.get("unit", "y")

            # Get rate for transfer
            zone = domain.get("_zone")
            rate = await domain_repo.get_rate(zone, period, unit)
            if rate is None:
                raise CommandError(
                    2306,
                    "Parameter value policy error",
                    reason=f"No rate found for {period}{unit} in zone {zone}"
                )

            # Check balance
            account_repo = await get_account_repo()
            balance = await account_repo.get_balance(session.account_id)
            if balance < rate:
                raise CommandError(
                    2104,
                    "Billing failure",
                    reason="Insufficient balance"
                )

            try:
                result = await domain_repo.request_transfer(
                    domain_name=domain_name,
                    requesting_account_id=session.account_id,
                    user_id=session.user_id,
                    auth_info=auth_info,
                    period=period,
                    unit=unit
                )
            except Exception as e:
                logger.error(f"Failed to request transfer for {domain_name}: {e}")
                raise CommandError(2400, "Command failed", reason=str(e))

            result_data = self.response_builder.build_domain_transfer_result(
                name=domain_name,
                tr_status="pending",
                re_id=result.get("reID"),
                re_date=result.get("reDate"),
                ac_id=result.get("acID"),
                ac_date=result.get("acDate"),
                ex_date=result.get("exDate")
            )

            logger.info(f"Transfer requested for domain: {domain_name}")

            return self.success_response(
                cl_trid=cl_trid,
                code=1001,
                msg="Command completed successfully; action pending",
                result_data=result_data
            )

        elif op == "approve":
            # Approve transfer - must be current sponsor
            if sponsoring_account != session.account_id:
                raise AuthorizationError(
                    "domain",
                    domain_name,
                    "Only current sponsoring registrar can approve transfer"
                )

            try:
                result = await domain_repo.approve_transfer(domain_name, session.user_id)
            except Exception as e:
                logger.error(f"Failed to approve transfer for {domain_name}: {e}")
                raise CommandError(2400, "Command failed", reason=str(e))

            logger.info(f"Transfer approved for domain: {domain_name}")
            return self.success_response(cl_trid=cl_trid)

        elif op == "reject":
            # Reject transfer - must be current sponsor
            if sponsoring_account != session.account_id:
                raise AuthorizationError(
                    "domain",
                    domain_name,
                    "Only current sponsoring registrar can reject transfer"
                )

            try:
                result = await domain_repo.reject_transfer(domain_name, session.user_id)
            except Exception as e:
                logger.error(f"Failed to reject transfer for {domain_name}: {e}")
                raise CommandError(2400, "Command failed", reason=str(e))

            logger.info(f"Transfer rejected for domain: {domain_name}")
            return self.success_response(cl_trid=cl_trid)

        elif op == "cancel":
            # Cancel transfer - must be requesting registrar
            transfer = await domain_repo.get_transfer_info(domain_name)
            if not transfer:
                raise CommandError(
                    2303,
                    "Object does not exist",
                    reason="No pending transfer for domain"
                )

            # Check if this registrar requested the transfer
            # (would need to look up account client ID)

            try:
                result = await domain_repo.cancel_transfer(domain_name, session.user_id)
            except Exception as e:
                logger.error(f"Failed to cancel transfer for {domain_name}: {e}")
                raise CommandError(2400, "Command failed", reason=str(e))

            logger.info(f"Transfer cancelled for domain: {domain_name}")
            return self.success_response(cl_trid=cl_trid)

    async def get_roid_from_command(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> Optional[str]:
        """Extract ROID for transaction logging."""
        domain_name = command.data.get("name")
        if domain_name:
            domain_repo = await get_domain_repo()
            return await domain_repo.get_roid(domain_name)
        return None


# Handler registry
DOMAIN_HANDLERS = {
    "check": DomainCheckHandler,
    "info": DomainInfoHandler,
    "create": DomainCreateHandler,
    "update": DomainUpdateHandler,
    "delete": DomainDeleteHandler,
    "renew": DomainRenewHandler,
    "transfer": DomainTransferHandler,
}


def get_domain_handler(command_type: str) -> Optional[ObjectCommandHandler]:
    """
    Get handler for domain command.

    Args:
        command_type: Command type (check, info, create, etc.)

    Returns:
        Handler instance or None
    """
    handler_class = DOMAIN_HANDLERS.get(command_type)
    if handler_class:
        return handler_class()
    return None
