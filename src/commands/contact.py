"""
Contact Commands

Handles EPP contact commands:
- check: Check contact availability
- info: Get contact information
- create: Create new contact
- update: Update contact
- delete: Delete contact
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
from src.database.repositories.contact_repo import get_contact_repo
from src.utils.roid_generator import generate_roid
from src.utils.password_utils import generate_auth_info, validate_auth_info
from src.validators.epp_validator import get_validator

logger = logging.getLogger("epp.commands.contact")


class ContactCheckHandler(ObjectCommandHandler):
    """
    Handle contact:check command.

    Checks availability of one or more contact IDs.
    """

    command_name = "check"
    object_type = "contact"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process contact:check command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Get contact IDs to check
        ids = data.get("ids", [])

        if not ids:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="At least one contact ID required"
            )

        # Check each contact
        contact_repo = await get_contact_repo()
        results = await contact_repo.check_multiple(ids)

        # Build response
        result_data = self.response_builder.build_contact_check_result(results)

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class ContactInfoHandler(ObjectCommandHandler):
    """
    Handle contact:info command.

    Returns detailed information about a contact.
    """

    command_name = "info"
    object_type = "contact"

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

        # Get contact data
        contact_repo = await get_contact_repo()
        contact = await contact_repo.get_by_uid(contact_id)

        if not contact:
            raise ObjectNotFoundError("contact", contact_id)

        # Check authorization for auth info
        include_auth = False
        sponsoring_account = contact.get("_account_id")

        if session.account_id == sponsoring_account:
            # Sponsoring registrar can see auth info
            include_auth = True
        elif auth_info:
            # Non-sponsor provided auth info - verify it
            if await contact_repo.verify_auth_info(contact_id, auth_info):
                include_auth = True

        # Reload with auth info if authorized
        if include_auth:
            contact = await contact_repo.get_by_uid(contact_id, include_auth=True)

        # Build response
        result_data = self.response_builder.build_contact_info_result(contact)

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
        contact_id = command.data.get("id")
        if contact_id:
            contact_repo = await get_contact_repo()
            return await contact_repo.get_roid(contact_id)
        return None


class ContactCreateHandler(ObjectCommandHandler):
    """
    Handle contact:create command.

    Creates a new contact.
    """

    command_name = "create"
    object_type = "contact"

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process contact:create command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Validate required fields
        contact_id = data.get("id")
        if not contact_id:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Contact ID required"
            )

        # Validate contact ID format
        validator = get_validator()
        valid, error = validator.validate_contact_id(contact_id)
        if not valid:
            raise CommandError(2005, "Parameter value syntax error", reason=error)

        # Validate email
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

        # Validate postal info - at least one required
        postal_int = data.get("postalInfo_int")
        postal_loc = data.get("postalInfo_loc")
        if not postal_int and not postal_loc:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="At least one postalInfo required"
            )

        # Validate voice phone if provided
        voice = data.get("voice")
        if voice:
            valid, error = validator.validate_phone(voice, data.get("voice_ext"))
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"Voice: {error}")

        # Validate fax if provided
        fax = data.get("fax")
        if fax:
            valid, error = validator.validate_phone(fax, data.get("fax_ext"))
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"Fax: {error}")

        # Validate country codes in postal info
        for ptype, postal in [("int", postal_int), ("loc", postal_loc)]:
            if postal and postal.get("cc"):
                valid, error = validator.validate_country_code(postal["cc"])
                if not valid:
                    raise CommandError(2005, "Parameter value syntax error", reason=f"PostalInfo {ptype}: {error}")

        # Check availability
        contact_repo = await get_contact_repo()
        avail, reason = await contact_repo.check_available(contact_id)
        if not avail:
            raise CommandError(
                2302,
                "Object exists",
                reason=f"Contact {contact_id} already exists"
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

        # Extract postal info - prefer international, fallback to localized
        postal = postal_int or postal_loc or {}

        # Handle street - can be string or list (street is directly in postal, not nested in addr)
        street = postal.get("street", [])
        if isinstance(street, str):
            street = [street]
        street1 = street[0] if len(street) > 0 else None
        street2 = street[1] if len(street) > 1 else None
        street3 = street[2] if len(street) > 2 else None

        # Create contact
        # Note: city, sp, pc, cc are directly in postal dict, not nested under addr
        try:
            contact = await contact_repo.create(
                contact_id=contact_id,
                roid=roid,
                account_id=session.account_id,
                user_id=session.user_id,
                email=email,
                auth_info=auth_info,
                name=postal.get("name"),
                org=postal.get("org"),
                street1=street1,
                street2=street2,
                street3=street3,
                city=postal.get("city"),
                state=postal.get("sp"),
                postcode=postal.get("pc"),
                country=postal.get("cc"),
                phone=voice,
                phone_ext=data.get("voice_ext"),
                fax=fax,
                fax_ext=data.get("fax_ext")
            )
        except Exception as e:
            logger.error(f"Failed to create contact {contact_id}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        # Build response
        result_data = self.response_builder.build_contact_create_result(
            contact_id=contact_id,
            cr_date=contact.get("crDate")
        )

        logger.info(f"Created contact: {contact_id} (ROID: {roid})")

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class ContactUpdateHandler(ObjectCommandHandler):
    """
    Handle contact:update command.

    Updates contact information.
    """

    command_name = "update"
    object_type = "contact"

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

        # Get contact and verify authorization
        contact_repo = await get_contact_repo()
        contact = await contact_repo.get_by_uid(contact_id)

        if not contact:
            raise ObjectNotFoundError("contact", contact_id)

        # Verify sponsoring registrar
        if contact.get("_account_id") != session.account_id:
            raise AuthorizationError("Only sponsoring registrar can update contact")

        # Validate update data
        validator = get_validator()

        # Validate email if being changed
        chg_data = data.get("chg", {})
        if chg_data.get("email"):
            valid, error = validator.validate_email(chg_data["email"])
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"Email: {error}")

        # Validate phone if being changed
        if chg_data.get("voice"):
            valid, error = validator.validate_phone(chg_data["voice"], chg_data.get("voice_ext"))
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"Voice: {error}")

        if chg_data.get("fax"):
            valid, error = validator.validate_phone(chg_data["fax"], chg_data.get("fax_ext"))
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"Fax: {error}")

        # Validate auth info if being changed
        if chg_data.get("authInfo"):
            valid, error = validate_auth_info(chg_data["authInfo"])
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"AuthInfo: {error}")

        # Extract add/rem status
        add_data = data.get("add", {})
        rem_data = data.get("rem", {})

        add_statuses = add_data.get("statuses", [])
        rem_statuses = rem_data.get("statuses", [])

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
            updated = await contact_repo.update(
                contact_id=contact_id,
                user_id=session.user_id,
                email=chg_data.get("email"),
                phone=chg_data.get("voice"),
                phone_ext=chg_data.get("voice_ext"),
                fax=chg_data.get("fax"),
                fax_ext=chg_data.get("fax_ext"),
                auth_info=chg_data.get("authInfo"),
                add_statuses=add_statuses,
                rem_statuses=rem_statuses
            )
        except Exception as e:
            logger.error(f"Failed to update contact {contact_id}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        logger.info(f"Updated contact: {contact_id}")

        return self.success_response(cl_trid=cl_trid)


class ContactDeleteHandler(ObjectCommandHandler):
    """
    Handle contact:delete command.

    Deletes a contact.
    """

    command_name = "delete"
    object_type = "contact"

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

        # Get contact and verify authorization
        contact_repo = await get_contact_repo()
        contact = await contact_repo.get_by_uid(contact_id)

        if not contact:
            raise ObjectNotFoundError("contact", contact_id)

        # Verify sponsoring registrar
        if contact.get("_account_id") != session.account_id:
            raise AuthorizationError("Only sponsoring registrar can delete contact")

        # Check if contact is in use
        in_use, usage = await contact_repo.is_in_use(contact_id)
        if in_use:
            raise CommandError(
                2305,
                "Object association prohibits operation",
                reason=usage
            )

        # Perform delete
        try:
            await contact_repo.delete(contact_id)
        except Exception as e:
            logger.error(f"Failed to delete contact {contact_id}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        logger.info(f"Deleted contact: {contact_id}")

        return self.success_response(cl_trid=cl_trid)

    async def get_roid_from_command(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> Optional[str]:
        """Extract ROID for transaction logging."""
        contact_id = command.data.get("id")
        if contact_id:
            contact_repo = await get_contact_repo()
            return await contact_repo.get_roid(contact_id)
        return None


# Handler registry
CONTACT_HANDLERS = {
    "check": ContactCheckHandler,
    "info": ContactInfoHandler,
    "create": ContactCreateHandler,
    "update": ContactUpdateHandler,
    "delete": ContactDeleteHandler,
}


def get_contact_handler(command_type: str) -> Optional[ObjectCommandHandler]:
    """
    Get handler for contact command.

    Args:
        command_type: Command type (check, info, create, etc.)

    Returns:
        Handler instance or None
    """
    handler_class = CONTACT_HANDLERS.get(command_type)
    if handler_class:
        return handler_class()
    return None
