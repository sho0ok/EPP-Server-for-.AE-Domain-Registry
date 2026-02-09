"""
AU Extension Commands

Handles .au TLD specific EPP extension commands per auext-1.1 schema:
- AuDomainModifyRegistrant: Correct eligibility data without changing legal registrant
- AuDomainTransferRegistrant: Transfer domain to new legal entity (charges create fee)

All commands delegate to ARI PL/SQL stored procedures for full parity with
the original C++ EPP server.

Namespace: urn:X-au:params:xml:ns:auext-1.1
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.commands.base import (
    ObjectCommandHandler,
    CommandError,
)
from src.core.session_manager import SessionInfo
from src.core.xml_processor import EPPCommand
from src.database.plsql_caller import get_plsql_caller

logger = logging.getLogger("epp.commands.au_extension")

# AU Extension namespace
AUEXT_NS = "urn:X-au:params:xml:ns:auext-1.1"

# Valid AU eligibility types per auext-1.1.xsd
AU_ELIGIBILITY_TYPES = [
    "Charity",
    "Child Care Centre",
    "Citizen/Resident",
    "Club",
    "Commercial Statutory Body",
    "Company",
    "Government School",
    "Higher Education Institution",
    "Incorporated Association",
    "Industry Body",
    "National Body",
    "Non-Government School",
    "Non-profit Organisation",
    "Other",
    "Partnership",
    "Pending TM Owner",
    "Political Party",
    "Pre-school",
    "Registered Business",
    "Religious/Church Group",
    "Research Organisation",
    "Sole Trader",
    "Trade Union",
    "Trademark Owner",
    "Training Organisation",
]

# Valid registrant ID types
AU_REGISTRANT_ID_TYPES = ["ACN", "ABN", "OTHER"]

# Valid eligibility ID types
AU_ELIGIBILITY_ID_TYPES = [
    "ACN", "ABN", "VIC BN", "NSW BN", "SA BN", "NT BN",
    "WA BN", "TAS BN", "ACT BN", "QLD BN", "TM", "OTHER"
]


class AuDomainModifyRegistrantHandler(ObjectCommandHandler):
    """
    Handle auext:update (domain modify registrant) command via epp_domain.domain_update().

    This command corrects AU extension data for .au domains where the
    legal registrant has NOT changed. Implemented as domain:update with
    AU extension data passed through p_extensions parameter.

    PL/SQL handles authorization, status validation, extension update,
    audit logging, and transaction recording.

    Per auext-1.1.xsd:
    - registrantName: Required
    - explanation: Required (max 1000 chars)
    - eligibilityType: Required
    - policyReason: Required (1-106)
    - registrantID + type: Optional
    - eligibilityName: Optional
    - eligibilityID + type: Optional
    """

    command_name = "au_modify_registrant"
    object_type = "domain"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AU domain modify registrant command."""
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

        # Get AU extension data
        au_data = extensions.get("auext", {})
        if not au_data:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="AU extension data required"
            )

        # Validate required fields
        registrant_name = au_data.get("registrantName")
        if not registrant_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="registrantName required in AU extension"
            )

        explanation = au_data.get("explanation")
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

        # Validate eligibility type (required for AU)
        eligibility_type = au_data.get("eligibilityType")
        if not eligibility_type:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="eligibilityType required in AU extension"
            )

        if eligibility_type not in AU_ELIGIBILITY_TYPES:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid eligibilityType: {eligibility_type}"
            )

        # Validate policy reason (required for AU, 1-106)
        policy_reason = au_data.get("policyReason")
        if policy_reason is None:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="policyReason required in AU extension"
            )

        try:
            policy_reason = int(policy_reason)
            if not 1 <= policy_reason <= 106:
                raise ValueError()
        except (ValueError, TypeError):
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason="policyReason must be integer 1-106"
            )

        # Validate registrant ID type if provided
        registrant_id_type = au_data.get("registrantIDType")
        if registrant_id_type and registrant_id_type not in AU_REGISTRANT_ID_TYPES:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid registrantIDType: {registrant_id_type}"
            )

        # Validate eligibility ID type if provided
        eligibility_id_type = au_data.get("eligibilityIDType")
        if eligibility_id_type and eligibility_id_type not in AU_ELIGIBILITY_ID_TYPES:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid eligibilityIDType: {eligibility_id_type}"
            )

        # Build extension data for domain_update p_extensions parameter
        new_values = {
            "registrantName": registrant_name,
            "eligibilityType": eligibility_type,
            "policyReason": str(policy_reason),
            "explanation": explanation,
        }
        if au_data.get("registrantID"):
            new_values["registrantIDValue"] = au_data["registrantID"]
        if registrant_id_type:
            new_values["registrantIDType"] = registrant_id_type
        if au_data.get("eligibilityName"):
            new_values["eligibilityName"] = au_data["eligibilityName"]
        if au_data.get("eligibilityID"):
            new_values["eligibilityIDValue"] = au_data["eligibilityID"]
        if eligibility_id_type:
            new_values["eligibilityIDType"] = eligibility_id_type

        extension_list = [{
            "extension": "au",
            "new_values": new_values,
            "reason": ""
        }]

        # Call epp_domain.domain_update() with extension data
        plsql = await get_plsql_caller()
        result = await plsql.domain_update(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=domain_name,
            extensions=extension_list
        )

        rc = result.get("response_code", 2400)
        if rc >= 2000:
            return self.response_builder.build_error(
                code=rc,
                message=result.get("response_message", "Command failed"),
                cl_trid=cl_trid,
                sv_trid=result.get("sv_trid")
            )

        logger.info(f"Modified AU registrant data for domain: {domain_name}")

        return self.response_builder.build_response(
            code=rc,
            message=result.get("response_message"),
            cl_trid=cl_trid,
            sv_trid=result.get("sv_trid")
        )


class AuDomainTransferRegistrantHandler(ObjectCommandHandler):
    """
    Handle auext:command/registrantTransfer command via epp_arext.registrant_transfer().

    Transfers a .au domain to a new legal registrant entity.
    PL/SQL handles domain lookup, status validation, billing, registrant data
    update, audit logging, and transaction recording.

    Per auext-1.1.xsd:
    - name: Domain name (required)
    - curExpDate: Current expiry date (required, prevents replay)
    - eligibilityType: Required
    - policyReason: Required (1-106)
    - registrantName: Required
    - explanation: Required (max 1000 chars)
    - period: Optional (new validity period)
    - registrantID + type: Optional
    - eligibilityName: Optional
    - eligibilityID + type: Optional
    """

    command_name = "au_transfer_registrant"
    object_type = "domain"
    plsql_managed = True

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process AU domain transfer registrant command."""
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

        # Required AU fields
        eligibility_type = data.get("eligibilityType")
        if not eligibility_type:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="eligibilityType required"
            )

        if eligibility_type not in AU_ELIGIBILITY_TYPES:
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
            if not 1 <= policy_reason <= 106:
                raise ValueError()
        except (ValueError, TypeError):
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason="policyReason must be integer 1-106"
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
        if registrant_id_type and registrant_id_type not in AU_REGISTRANT_ID_TYPES:
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid registrantIDType: {registrant_id_type}"
            )

        eligibility_id_type = data.get("eligibilityIDType")
        if eligibility_id_type and eligibility_id_type not in AU_ELIGIBILITY_ID_TYPES:
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
            "extension": "auext",
            "new_values": new_values,
            "reason": ""
        }

        # Call PL/SQL stored procedure
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
        result_data = self.response_builder.build_au_transfer_registrant_result(
            name=result.get("name", domain_name),
            ex_date=result.get("ex_date")
        )

        logger.info(f"Transferred AU registrant for domain: {domain_name}")

        return self.response_builder.build_response(
            code=rc,
            message=result.get("response_message"),
            cl_trid=cl_trid,
            sv_trid=result.get("sv_trid"),
            result_data=result_data
        )


# Handler registry for AU extension commands
AU_EXTENSION_HANDLERS = {
    "au_modify_registrant": AuDomainModifyRegistrantHandler,
    "au_transfer_registrant": AuDomainTransferRegistrantHandler,
}


def get_au_extension_handler(command_type: str) -> Optional[ObjectCommandHandler]:
    """
    Get handler for AU extension command.

    Args:
        command_type: Command type (au_modify_registrant, au_transfer_registrant)

    Returns:
        Handler instance or None
    """
    handler_class = AU_EXTENSION_HANDLERS.get(command_type)
    if handler_class:
        return handler_class()
    return None
