"""
AE Extension Commands

Handles .ae TLD specific EPP extension commands per aeext-1.0 schema:
- AeDomainModifyRegistrant: Correct eligibility data without changing legal registrant
- AeDomainTransferRegistrant: Transfer domain to new legal entity (charges create fee)

Namespace: urn:X-ae:params:xml:ns:aeext-1.0
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
    Handle aeext:command/registrantTransfer command via epp_arext.registrant_transfer().

    Transfers a .ae domain to a new legal registrant entity.
    PL/SQL handles domain lookup, status validation, billing, registrant data
    update, audit logging, and transaction recording.

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
    plsql_managed = True

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

        # Build registrant extension_t data for PL/SQL
        new_values = {
            "registrantName": registrant_name,
            "eligibilityType": eligibility_type,
            "policyReason": str(policy_reason),
            "explanation": explanation,
        }
        # Add optional fields
        if data.get("registrantID"):
            new_values["registrantID"] = data["registrantID"]
        if registrant_id_type:
            new_values["registrantIDType"] = registrant_id_type
        if data.get("eligibilityName"):
            new_values["eligibilityName"] = data["eligibilityName"]
        if data.get("eligibilityID"):
            new_values["eligibilityID"] = data["eligibilityID"]
        if eligibility_id_type:
            new_values["eligibilityIDType"] = eligibility_id_type

        registrant_data = {
            "extension": "aeext",
            "new_values": new_values,
            "reason": ""
        }

        # Call PL/SQL stored procedure
        from src.database.plsql_caller import get_plsql_caller
        plsql = await get_plsql_caller()
        result = await plsql.registrant_transfer(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=domain_name,
            cur_exp_date=cur_exp_date,
            period=period,
            period_unit=period_unit,
            registrant_data=registrant_data
        )

        rc = result.get("response_code", 2400)
        if rc >= 2000:
            return self.response_builder.build_error(
                code=rc,
                message=result.get("response_message", "Command failed"),
                cl_trid=cl_trid,
                sv_trid=result.get("sv_trid")
            )

        # Build response with new expiry date
        result_data = self.response_builder.build_ae_transfer_registrant_result(
            name=result.get("name", domain_name),
            ex_date=result.get("ex_date")
        )

        logger.info(f"Transferred AE registrant for domain: {domain_name}")

        return self.response_builder.build_response(
            code=rc,
            message=result.get("response_message"),
            cl_trid=cl_trid,
            sv_trid=result.get("sv_trid"),
            result_data=result_data
        )


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
