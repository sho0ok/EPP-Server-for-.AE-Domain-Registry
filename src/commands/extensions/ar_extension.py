"""
AR Extension Commands

Handles AusRegistry-specific EPP extension commands per arext-1.0 schema:
- ArUndelete: Restore a deleted domain from redemption grace period
- ArUnrenew: Cancel a pending renewal and revert expiry date
- ArPolicyDelete: Delete domain for policy violation
- ArPolicyUndelete: Restore domain deleted for policy violation

Namespace: urn:X-ar:params:xml:ns:arext-1.0
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from src.commands.base import (
    ObjectCommandHandler,
    CommandError,
    ObjectNotFoundError,
    AuthorizationError,
)
from src.core.session_manager import SessionInfo
from src.core.xml_processor import EPPCommand
from src.database.repositories.domain_repo import get_domain_repo

logger = logging.getLogger("epp.commands.ar_extension")

# AR Extension namespace
AREXT_NS = "urn:X-ar:params:xml:ns:arext-1.0"


class ArUndeleteHandler(ObjectCommandHandler):
    """
    Handle arext:command/undelete command.

    This is a PROTOCOL EXTENSION command that restores a domain
    from the pending delete / redemption grace period.

    Per arext-1.0.xsd, the command contains only:
    - name: Domain name to restore
    """

    command_name = "ar_undelete"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AR undelete command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Get domain name
        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        # Get domain and verify
        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        # Verify sponsoring registrar
        if domain.get("_account_id") != session.account_id:
            raise AuthorizationError("Only sponsoring registrar can undelete domain")

        # Check domain is in deletable state (pendingDelete or redemptionPeriod)
        statuses = domain.get("statuses", [])
        is_restorable = False
        for status in statuses:
            status_value = status.get("s") if isinstance(status, dict) else status
            if status_value in ("pendingDelete", "redemptionPeriod"):
                is_restorable = True
                break

        if not is_restorable:
            raise CommandError(
                2304,
                "Object status prohibits operation",
                reason="Domain is not in pending delete or redemption status"
            )

        # Perform the undelete
        try:
            await domain_repo.undelete(
                domain_roid=domain.get("roid"),
                user_id=session.user_id
            )
        except Exception as e:
            logger.error(f"Failed to undelete {domain_name}: {e}")
            raise CommandError(2400, "Command failed", reason=str(e))

        # Build response
        result_data = self.response_builder.build_ar_undelete_result(name=domain_name)

        logger.info(f"Undeleted domain: {domain_name}")

        return self.success_response(cl_trid=cl_trid, result_data=result_data)

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


class ArUnrenewHandler(ObjectCommandHandler):
    """
    Handle arext:command/unrenew command.

    This is a PROTOCOL EXTENSION command that cancels a pending renewal
    and reverts the domain to its previous expiry date.

    Per arext-1.0.xsd, the command contains only:
    - name: Domain name to unrenew
    """

    command_name = "ar_unrenew"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AR unrenew command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Get domain name
        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        # Get domain and verify
        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        # Verify sponsoring registrar
        if domain.get("_account_id") != session.account_id:
            raise AuthorizationError("Only sponsoring registrar can unrenew domain")

        # Check domain status
        statuses = domain.get("statuses", [])
        for status in statuses:
            status_value = status.get("s") if isinstance(status, dict) else status
            if status_value in ("clientUpdateProhibited", "serverUpdateProhibited"):
                raise CommandError(
                    2304,
                    "Object status prohibits operation",
                    reason=f"Domain has {status_value} status"
                )

        # Perform the unrenew
        try:
            result = await domain_repo.unrenew(
                domain_roid=domain.get("roid"),
                user_id=session.user_id,
                account_id=session.account_id
            )
        except Exception as e:
            logger.error(f"Failed to unrenew {domain_name}: {e}")
            raise CommandError(2400, "Command failed", reason=str(e))

        # Build response with reverted expiry date
        result_data = self.response_builder.build_ar_unrenew_result(
            name=domain_name,
            ex_date=result.get("exDate")
        )

        logger.info(f"Unrenewed domain: {domain_name}")

        return self.success_response(cl_trid=cl_trid, result_data=result_data)

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


class ArPolicyDeleteHandler(ObjectCommandHandler):
    """
    Handle arext:command/policyDelete command.

    This is a PROTOCOL EXTENSION command for registry-initiated or
    policy-based domain deletion. The domain is deleted immediately
    without a grace period.

    Per arext-1.0.xsd, the command contains:
    - name: Domain name to delete
    - reason: Optional reason for deletion
    """

    command_name = "ar_policy_delete"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AR policy delete command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Get domain name
        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        reason = data.get("reason")

        # Get domain and verify
        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        # Verify sponsoring registrar OR registry operator permission
        if domain.get("_account_id") != session.account_id:
            # Check if user has registry operator permissions
            if not session.is_registry_operator:
                raise AuthorizationError(
                    "Only sponsoring registrar or registry operator can policy delete"
                )

        # Perform the policy delete
        try:
            await domain_repo.policy_delete(
                domain_roid=domain.get("roid"),
                user_id=session.user_id,
                reason=reason
            )
        except Exception as e:
            logger.error(f"Failed to policy delete {domain_name}: {e}")
            raise CommandError(2400, "Command failed", reason=str(e))

        logger.info(f"Policy deleted domain: {domain_name} (reason: {reason})")

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


class ArPolicyUndeleteHandler(ObjectCommandHandler):
    """
    Handle arext:command/policyUndelete command.

    This is a PROTOCOL EXTENSION command that restores a domain
    that was deleted due to policy violation.

    Per arext-1.0.xsd, the command contains only:
    - name: Domain name to restore
    """

    command_name = "ar_policy_undelete"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AR policy undelete command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Get domain name
        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        # Get domain and verify
        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        # Verify registry operator permission
        if not session.is_registry_operator:
            raise AuthorizationError(
                "Only registry operator can policy undelete domains"
            )

        # Perform the policy undelete
        try:
            await domain_repo.policy_undelete(
                domain_roid=domain.get("roid"),
                user_id=session.user_id
            )
        except Exception as e:
            logger.error(f"Failed to policy undelete {domain_name}: {e}")
            raise CommandError(2400, "Command failed", reason=str(e))

        # Build response
        result_data = self.response_builder.build_ar_undelete_result(name=domain_name)

        logger.info(f"Policy undeleted domain: {domain_name}")

        return self.success_response(cl_trid=cl_trid, result_data=result_data)

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
