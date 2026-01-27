"""
AE Extension Commands

Handles .ae TLD specific EPP extension commands per aeext-1.0 schema:
- AeDomainModifyRegistrant: Correct eligibility data without changing legal registrant
- AeDomainTransferRegistrant: Transfer domain to new legal entity (charges create fee)

Namespace: urn:X-ae:params:xml:ns:aeext-1.0
"""

import logging
from datetime import datetime, timedelta
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
from src.database.repositories.extension_repo import get_extension_repo

logger = logging.getLogger("epp.commands.ae_extension")

# AE Extension namespace
AEEXT_NS = "urn:X-ae:params:xml:ns:aeext-1.0"

# Valid AE eligibility types per aeext-1.0.xsd
AE_ELIGIBILITY_TYPES = [
    "Trade License",
    "Freezone Trade License",
    "Trademark",
    "Freezone Trademark",
    "Trade License (IT)",
    "Freezone Trade License (IT)",
    "Trademark (IT)",
    "Freezone Trademark (IT)",
    "Legacy",
    "Legacy - Approved",
    "Citizen",
    "Permanent Resident",
    "Sporting Organisation",
    "Charitable Organisation",
    "Religious Organisation",
    "University",
    "Technical College",
    "School",
    "Academy",
    "Government Approved",
]

# Valid registrant ID types
AE_REGISTRANT_ID_TYPES = ["Trade License"]

# Valid eligibility ID types
AE_ELIGIBILITY_ID_TYPES = ["Trademark"]


class AeDomainModifyRegistrantHandler(ObjectCommandHandler):
    """
    Handle aeext:update (domain modify registrant) command.

    This command corrects AE extension data for .ae domains where the
    legal registrant has NOT changed. Use this to fix incorrectly
    specified eligibility data.

    This is implemented as a domain:update command with aeext:update extension.

    Per aeext-1.0.xsd:
    - registrantName: Required
    - explanation: Required (max 1000 chars)
    - eligibilityType: Optional
    - policyReason: Optional (1-99)
    - registrantID + type: Optional
    - eligibilityName: Optional
    - eligibilityID + type: Optional
    """

    command_name = "ae_modify_registrant"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AE domain modify registrant command."""
        cl_trid = command.client_transaction_id
        data = command.data
        extensions = command.extensions

        # Get domain name from the update command
        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        # Get AE extension data
        ae_data = extensions.get("aeext", {})
        if not ae_data:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="AE extension data required"
            )

        # Validate required fields
        registrant_name = ae_data.get("registrantName")
        if not registrant_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="registrantName required in AE extension"
            )

        explanation = ae_data.get("explanation")
        if not explanation:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="explanation required for modify registrant"
            )

        if len(explanation) > 1000:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason="explanation must not exceed 1000 characters"
            )

        # Validate eligibility type if provided
        eligibility_type = ae_data.get("eligibilityType")
        if eligibility_type and eligibility_type not in AE_ELIGIBILITY_TYPES:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid eligibilityType: {eligibility_type}"
            )

        # Validate policy reason if provided (1-99)
        policy_reason = ae_data.get("policyReason")
        if policy_reason is not None:
            try:
                policy_reason = int(policy_reason)
                if not 1 <= policy_reason <= 99:
                    raise ValueError()
            except (ValueError, TypeError):
                raise CommandError(
                    2005,
                    "Parameter value syntax error",
                    reason="policyReason must be integer 1-99"
                )

        # Validate registrant ID type if provided
        registrant_id_type = ae_data.get("registrantIDType")
        if registrant_id_type and registrant_id_type not in AE_REGISTRANT_ID_TYPES:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid registrantIDType: {registrant_id_type}"
            )

        # Validate eligibility ID type if provided
        eligibility_id_type = ae_data.get("eligibilityIDType")
        if eligibility_id_type and eligibility_id_type not in AE_ELIGIBILITY_ID_TYPES:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid eligibilityIDType: {eligibility_id_type}"
            )

        # Get domain and verify authorization
        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        # Verify sponsoring registrar
        if domain.get("_account_id") != session.account_id:
            raise AuthorizationError("Only sponsoring registrar can modify registrant data")

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

        # Perform the update
        extension_repo = await get_extension_repo()
        try:
            await extension_repo.update_ae_registrant_data(
                domain_roid=domain.get("roid"),
                user_id=session.user_id,
                registrant_name=registrant_name,
                explanation=explanation,
                eligibility_type=eligibility_type,
                policy_reason=policy_reason,
                registrant_id=ae_data.get("registrantID"),
                registrant_id_type=registrant_id_type,
                eligibility_name=ae_data.get("eligibilityName"),
                eligibility_id=ae_data.get("eligibilityID"),
                eligibility_id_type=eligibility_id_type,
            )
        except Exception as e:
            logger.error(f"Failed to modify registrant for {domain_name}: {e}")
            raise CommandError(2400, "Command failed", reason=str(e))

        logger.info(f"Modified AE registrant data for domain: {domain_name}")

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


class AeDomainTransferRegistrantHandler(ObjectCommandHandler):
    """
    Handle aeext:command/registrantTransfer command.

    This is a PROTOCOL EXTENSION command (not a standard EPP command).
    It transfers a .ae domain to a new legal registrant entity.

    This is different from standard domain transfer - it changes legal ownership
    and results in:
    - New validity period starting from transfer completion
    - Create fee being charged to the requesting client

    Per aeext-1.0.xsd:
    - name: Domain name (required)
    - curExpDate: Current expiry date (required, prevents replay)
    - eligibilityType: Required
    - policyReason: Required (1-99)
    - registrantName: Required
    - explanation: Required (max 1000 chars)
    - period: Optional (new validity period)
    - registrantID + type: Optional
    - eligibilityName: Optional
    - eligibilityID + type: Optional
    """

    command_name = "ae_transfer_registrant"
    object_type = "domain"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AE domain transfer registrant command."""
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

        # Current expiry date (required to prevent replay attacks)
        cur_exp_date = data.get("curExpDate")
        if not cur_exp_date:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="curExpDate required for registrant transfer"
            )

        # Required AE fields
        eligibility_type = data.get("eligibilityType")
        if not eligibility_type:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="eligibilityType required"
            )

        if eligibility_type not in AE_ELIGIBILITY_TYPES:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid eligibilityType: {eligibility_type}"
            )

        policy_reason = data.get("policyReason")
        if policy_reason is None:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="policyReason required"
            )

        try:
            policy_reason = int(policy_reason)
            if not 1 <= policy_reason <= 99:
                raise ValueError()
        except (ValueError, TypeError):
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason="policyReason must be integer 1-99"
            )

        registrant_name = data.get("registrantName")
        if not registrant_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="registrantName required"
            )

        explanation = data.get("explanation")
        if not explanation:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="explanation required"
            )

        if len(explanation) > 1000:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason="explanation must not exceed 1000 characters"
            )

        # Optional period (defaults to 1 year)
        period = data.get("period", 1)
        period_unit = data.get("period_unit", "y")

        # Validate optional ID types
        registrant_id_type = data.get("registrantIDType")
        if registrant_id_type and registrant_id_type not in AE_REGISTRANT_ID_TYPES:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid registrantIDType: {registrant_id_type}"
            )

        eligibility_id_type = data.get("eligibilityIDType")
        if eligibility_id_type and eligibility_id_type not in AE_ELIGIBILITY_ID_TYPES:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid eligibilityIDType: {eligibility_id_type}"
            )

        # Get domain and verify
        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        # Verify sponsoring registrar
        if domain.get("_account_id") != session.account_id:
            raise AuthorizationError("Only sponsoring registrar can transfer registrant")

        # Verify current expiry date matches (prevents replay)
        actual_exp_date = domain.get("exDate", "")
        if actual_exp_date:
            # Normalize to date only for comparison
            if isinstance(actual_exp_date, str):
                actual_date = actual_exp_date[:10]  # YYYY-MM-DD
            else:
                actual_date = actual_exp_date.strftime("%Y-%m-%d")

            if isinstance(cur_exp_date, str):
                provided_date = cur_exp_date[:10]
            else:
                provided_date = cur_exp_date.strftime("%Y-%m-%d")

            if actual_date != provided_date:
                raise CommandError(
                    2306,
                    "Parameter value policy error",
                    reason=f"curExpDate mismatch: expected {actual_date}"
                )

        # Check domain status
        statuses = domain.get("statuses", [])
        for status in statuses:
            status_value = status.get("s") if isinstance(status, dict) else status
            if status_value in ("clientUpdateProhibited", "serverUpdateProhibited",
                               "clientTransferProhibited", "serverTransferProhibited"):
                raise CommandError(
                    2304,
                    "Object status prohibits operation",
                    reason=f"Domain has {status_value} status"
                )

        # Get zone and rate for billing
        zone = domain.get("_zone")
        rate = await domain_repo.get_rate(zone, period, period_unit)
        if rate is None:
            raise CommandError(
                2306,
                "Parameter value policy error",
                reason=f"No rate found for {period}{period_unit} in zone {zone}"
            )

        # Check balance (registrant transfer charges create fee)
        account_repo = await get_account_repo()
        balance = await account_repo.get_balance(session.account_id)
        if balance < rate:
            raise CommandError(
                2104,
                "Billing failure",
                reason="Insufficient balance for registrant transfer"
            )

        # Perform the registrant transfer
        extension_repo = await get_extension_repo()
        try:
            result = await extension_repo.transfer_ae_registrant(
                domain_roid=domain.get("roid"),
                domain_name=domain_name,
                account_id=session.account_id,
                user_id=session.user_id,
                registrant_name=registrant_name,
                explanation=explanation,
                eligibility_type=eligibility_type,
                policy_reason=policy_reason,
                period=period,
                period_unit=period_unit,
                registrant_id=data.get("registrantID"),
                registrant_id_type=registrant_id_type,
                eligibility_name=data.get("eligibilityName"),
                eligibility_id=data.get("eligibilityID"),
                eligibility_id_type=eligibility_id_type,
                rate=rate,
            )
        except Exception as e:
            logger.error(f"Failed to transfer registrant for {domain_name}: {e}")
            raise CommandError(2400, "Command failed", reason=str(e))

        # Build response with new expiry date
        result_data = self.response_builder.build_ae_transfer_registrant_result(
            name=domain_name,
            ex_date=result.get("exDate")
        )

        logger.info(f"Transferred AE registrant for domain: {domain_name}")

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
            return await domain_repo.get_roid(domain_name)
        return None


# Handler registry for AE extension commands
AE_EXTENSION_HANDLERS = {
    "ae_modify_registrant": AeDomainModifyRegistrantHandler,
    "ae_transfer_registrant": AeDomainTransferRegistrantHandler,
}


def get_ae_extension_handler(command_type: str) -> Optional[ObjectCommandHandler]:
    """
    Get handler for AE extension command.

    Args:
        command_type: Command type (ae_modify_registrant, ae_transfer_registrant)

    Returns:
        Handler instance or None
    """
    handler_class = AE_EXTENSION_HANDLERS.get(command_type)
    if handler_class:
        return handler_class()
    return None
