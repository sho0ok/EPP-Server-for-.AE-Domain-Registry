"""
Domain Commands

Handles EPP domain commands by calling ARI's PL/SQL stored procedures directly.
This is the same approach used by the old C++ EPP server - it called
epp_domain.domain_create(), epp_domain.domain_check(), etc.

The stored procedures handle all internal logic:
- ROID generation
- Registry object management
- Domain record creation/update/deletion
- Billing and rate calculation
- Audit logging
- Transaction logging
- Status management
- Contact/nameserver associations
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
from src.database.plsql_caller import get_plsql_caller
from src.database.repositories.domain_repo import get_domain_repo
from src.database.repositories.extension_repo import get_extension_repo
from src.utils.password_utils import generate_auth_info, validate_auth_info
from src.validators.epp_validator import get_validator

logger = logging.getLogger("epp.commands.domain")


def _plsql_response_to_epp_error(response_code: int, response_message: str) -> CommandError:
    """
    Convert a PL/SQL stored procedure response to a CommandError.

    The ARI stored procedures return EPP response codes (1000, 2302, etc.)
    directly in the epp_response_t result.
    """
    return CommandError(
        code=response_code,
        message=response_message or "Command failed"
    )


class DomainCheckHandler(ObjectCommandHandler):
    """
    Handle domain:check command.

    Calls epp_domain.domain_check() stored procedure.
    """

    command_name = "check"
    object_type = "domain"
    plsql_managed = True  # PL/SQL proc handles transaction logging

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:check command via PL/SQL."""
        cl_trid = command.client_transaction_id
        data = command.data

        names = data.get("names", [])
        if not names:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="At least one domain name required"
            )

        # Call ARI's stored procedure directly
        plsql = await get_plsql_caller()
        result = await plsql.domain_check(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            domain_names=names
        )

        response_code = result.get("response_code", 2400)

        # Check for error response
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        # Build response from PL/SQL results
        results = result.get("results", [])
        result_data = self.response_builder.build_domain_check_result(results)

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class DomainInfoHandler(ObjectCommandHandler):
    """
    Handle domain:info command.

    Uses domain_repo for reading (since we need to build detailed XML response
    with extensions, DNSSEC, IDN, KV data). The stored procedure returns
    complex nested objects that are harder to extract.
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
        hosts_filter = data.get("hosts", "all")

        # Get domain data via repository (for detailed info with extensions)
        domain_repo = await get_domain_repo()
        domain = await domain_repo.get_by_name(domain_name)

        if not domain:
            raise ObjectNotFoundError("domain", domain_name)

        # Check authorization for auth info
        include_auth = False
        sponsoring_account = domain.get("_account_id")

        if session.account_id == sponsoring_account:
            include_auth = True
        elif auth_info:
            if await domain_repo.verify_auth_info(domain_name, auth_info):
                include_auth = True

        if include_auth:
            domain = await domain_repo.get_by_name(domain_name, include_auth=True)

        # Filter hosts
        if hosts_filter == "none":
            domain["nameservers"] = []
            domain["hosts"] = []
        elif hosts_filter == "del":
            domain["hosts"] = []
        elif hosts_filter == "sub":
            domain["nameservers"] = []

        # Get extension data
        extension_repo = await get_extension_repo()
        domain_roid = domain.get("roid")
        extension_data = await extension_repo.get_domain_extension_data(domain_roid)

        extensions_response = None
        if extension_data:
            extensions_response = self._format_extension_data(extension_data)

        # Get Phase 7-11 extension data
        extension_elements = []

        try:
            secdns_data = await extension_repo.get_domain_secdns_data(domain_roid)
            if secdns_data:
                secdns_elem = self.response_builder.build_secdns_info_data(secdns_data)
                if secdns_elem is not None:
                    extension_elements.append(secdns_elem)
        except Exception:
            pass

        try:
            idn_data = await extension_repo.get_domain_idn_data(domain_roid)
            if idn_data:
                idn_elem = self.response_builder.build_idn_info_data(
                    user_form=idn_data.get("USER_FORM"),
                    language=idn_data.get("LANGUAGE"),
                    canonical_form=idn_data.get("CANONICAL_FORM")
                )
                if idn_elem is not None:
                    extension_elements.append(idn_elem)
        except Exception:
            pass

        try:
            variant_data = await extension_repo.get_domain_variants(domain_roid)
            if variant_data:
                variants = [
                    {"name": v.get("VARIANT_NAME"), "userForm": v.get("USER_FORM")}
                    for v in variant_data
                ]
                variant_elem = self.response_builder.build_variant_info_data(variants)
                if variant_elem is not None:
                    extension_elements.append(variant_elem)
        except Exception:
            pass

        try:
            kv_data = await extension_repo.get_domain_kv_data(domain_roid)
            if kv_data:
                kv_elem = self.response_builder.build_kv_info_data(kv_data)
                if kv_elem is not None:
                    extension_elements.append(kv_elem)
        except Exception:
            pass

        # Set audit log
        self.set_transaction_data(
            roid=domain_roid,
            audit_log=f"Domain Info: {domain_name}"
        )

        # Build response
        result_data = self.response_builder.build_domain_info_result(domain)

        final_extensions = None
        if extensions_response or extension_elements:
            from lxml import etree
            ext_container = etree.Element("{urn:ietf:params:xml:ns:epp-1.0}extension")

            if extensions_response:
                old_ext_xml = self.response_builder.build_extensions_response(extensions_response)
                if old_ext_xml is not None:
                    for child in old_ext_xml:
                        ext_container.append(child)

            for elem in extension_elements:
                ext_container.append(elem)

            if len(ext_container) > 0:
                final_extensions = ext_container

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data,
            extensions=final_extensions
        )

    def _format_extension_data(
        self, extension_data: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, str]]:
        """Format extension data for EPP response."""
        result: Dict[str, Dict[str, str]] = {}
        for row in extension_data:
            ext_name = row.get("EXT_NAME")
            field_key = row.get("FIELD_KEY")
            value = row.get("VALUE")
            if ext_name and field_key:
                if ext_name not in result:
                    result[ext_name] = {"_uri": row.get("EXT_URI", "")}
                result[ext_name][field_key] = value
        return result

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

    Calls epp_domain.domain_create() stored procedure directly.
    The stored procedure handles EVERYTHING internally:
    - Domain availability check
    - ROID generation
    - Registry object creation
    - Domain/registration records
    - Contact/nameserver associations
    - Billing (rate lookup, balance check, debit)
    - Audit logging
    - Transaction logging
    """

    command_name = "create"
    object_type = "domain"
    plsql_managed = True  # PL/SQL proc handles transaction logging

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:create command via PL/SQL."""
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

        registrant_id = data.get("registrant")
        if not registrant_id:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Registrant contact required"
            )

        # Get period
        period = data.get("period", 1)
        unit = data.get("unit", "y")

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

        # Build extension data for the PL/SQL call
        extension_list = self._build_extensions(command.extensions)

        # Build DNSSEC data
        dnssec_data = None
        if "secDNS" in command.extensions:
            secdns = command.extensions["secDNS"]
            dnssec_data = {
                "urgent": 0,
                "remove_all": 0,
                "maxSigLife": secdns.get("maxSigLife"),
                "dsData": secdns.get("dsData", []),
                "keyData": secdns.get("keyData", [])
            }

        # IDN language
        idna_language = None
        if "idnadomain" in command.extensions:
            idn = command.extensions["idnadomain"]
            idna_language = idn.get("language")

        # Call ARI's stored procedure - it handles EVERYTHING
        plsql = await get_plsql_caller()
        result = await plsql.domain_create(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=domain_name,
            period=period,
            period_unit=unit,
            nameservers=nameservers,
            registrant=registrant_id,
            contacts=contacts,
            auth_info=auth_info,
            userform=domain_name,  # For non-IDN domains, userform = domain name
            idna_language=idna_language,
            extensions=extension_list,
            dnssec=dnssec_data
        )

        response_code = result.get("response_code", 2400)

        # Check for error response from stored procedure
        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        # Build success response
        result_data = self.response_builder.build_domain_create_result(
            name=result.get("cr_name", domain_name),
            cr_date=result.get("cr_date"),
            ex_date=result.get("ex_date")
        )

        logger.info(f"Created domain via PL/SQL: {domain_name}")

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )

    def _build_extensions(self, extensions: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """Build extension list for PL/SQL call from parsed EPP extensions."""
        if not extensions:
            return None

        result = []

        # AE Eligibility extension
        if "aeEligibility" in extensions:
            ae_ext = extensions["aeEligibility"]
            fields = ae_ext.get("fields", {})
            if fields:
                result.append({
                    "extension": "aeEligibility",
                    "new_values": fields,
                    "reason": ""
                })

        # AE Domain extension
        if "aeDomain" in extensions:
            ae_dom = extensions["aeDomain"]
            fields = ae_dom.get("fields", {})
            if fields:
                result.append({
                    "extension": "aeDomain",
                    "new_values": fields,
                    "reason": ""
                })

        # Generic extensions
        for ext_name, ext_data in extensions.items():
            if ext_name in ("aeEligibility", "aeDomain", "secDNS", "idnadomain", "kv", "variant", "sync"):
                continue
            if isinstance(ext_data, dict):
                fields = ext_data.get("data") or ext_data.get("fields", {})
                if fields:
                    result.append({
                        "extension": ext_name,
                        "new_values": fields,
                        "reason": ""
                    })

        return result if result else None


class DomainUpdateHandler(ObjectCommandHandler):
    """
    Handle domain:update command.

    Calls epp_domain.domain_update() stored procedure.
    """

    command_name = "update"
    object_type = "domain"
    plsql_managed = True  # PL/SQL proc handles transaction logging

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:update command via PL/SQL."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        # Parse update data
        add_data = data.get("add", {})
        rem_data = data.get("rem", {})
        chg_data = data.get("chg", {})

        add_contacts = add_data.get("contacts", [])
        rem_contacts = rem_data.get("contacts", [])
        add_nameservers = add_data.get("ns", [])
        rem_nameservers = rem_data.get("ns", [])
        add_statuses_raw = add_data.get("statuses", [])
        rem_statuses_raw = rem_data.get("statuses", [])

        # Normalize statuses
        add_statuses = [
            s.get("s") if isinstance(s, dict) else s for s in add_statuses_raw
        ]
        rem_statuses = [
            s.get("s") if isinstance(s, dict) else s for s in rem_statuses_raw
        ]
        add_statuses = [s for s in add_statuses if s]
        rem_statuses = [s for s in rem_statuses if s]

        registrant_id = chg_data.get("registrant")
        auth_info = chg_data.get("authInfo")

        if auth_info:
            valid, error = validate_auth_info(auth_info)
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"AuthInfo: {error}")

        # Build extensions
        extension_list = self._build_update_extensions(command.extensions)

        # Get expire_date from sync extension if present
        expire_date = None
        if "sync" in command.extensions:
            sync = command.extensions["sync"]
            exp_str = sync.get("exDate")
            if exp_str:
                try:
                    if "T" in exp_str:
                        expire_date = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                    else:
                        expire_date = datetime.strptime(exp_str, "%Y-%m-%d")
                except ValueError:
                    pass

        # Call ARI's stored procedure
        plsql = await get_plsql_caller()
        result = await plsql.domain_update(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=domain_name,
            add_ns=add_nameservers or None,
            rem_ns=rem_nameservers or None,
            add_contacts=add_contacts or None,
            rem_contacts=rem_contacts or None,
            add_statuses=add_statuses or None,
            rem_statuses=rem_statuses or None,
            chg_registrant=registrant_id,
            chg_authinfo=auth_info,
            extensions=extension_list,
            expire_date=expire_date
        )

        response_code = result.get("response_code", 2400)

        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        logger.info(f"Updated domain via PL/SQL: {domain_name}")
        return self.success_response(cl_trid=cl_trid)

    def _build_update_extensions(self, extensions: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """Build extension list for domain update PL/SQL call."""
        if not extensions:
            return None

        result = []
        for ext_name, ext_data in extensions.items():
            if ext_name in ("secDNS", "variant", "sync", "kv"):
                continue
            if isinstance(ext_data, dict):
                fields = ext_data.get("data") or ext_data.get("fields", {})
                if fields:
                    result.append({
                        "extension": ext_name,
                        "new_values": fields,
                        "reason": ""
                    })

        return result if result else None

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


class DomainDeleteHandler(ObjectCommandHandler):
    """
    Handle domain:delete command.

    Calls epp_domain.domain_delete() stored procedure.
    """

    command_name = "delete"
    object_type = "domain"
    plsql_managed = True  # PL/SQL proc handles transaction logging

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:delete command via PL/SQL."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        # Call ARI's stored procedure
        plsql = await get_plsql_caller()
        result = await plsql.domain_delete(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=domain_name
        )

        response_code = result.get("response_code", 2400)

        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        logger.info(f"Deleted domain via PL/SQL: {domain_name}")

        # The stored procedure determines the response code
        # (1000 for immediate delete, 1001 for pending delete)
        return self.success_response(
            cl_trid=cl_trid,
            code=response_code,
            message=result.get("response_message")
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

    Calls epp_domain.domain_renew() stored procedure.
    """

    command_name = "renew"
    object_type = "domain"
    plsql_managed = True  # PL/SQL proc handles transaction logging

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:renew command via PL/SQL."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

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

        period = data.get("period", 1)
        unit = data.get("unit", "y")

        # Call ARI's stored procedure
        plsql = await get_plsql_caller()
        result = await plsql.domain_renew(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=domain_name,
            cur_exp_date=current_expiry,
            period=period,
            period_unit=unit
        )

        response_code = result.get("response_code", 2400)

        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        # Build response
        result_data = self.response_builder.build_domain_renew_result(
            name=result.get("name", domain_name),
            ex_date=result.get("ex_date")
        )

        logger.info(f"Renewed domain via PL/SQL: {domain_name}")

        return self.success_response(
            cl_trid=cl_trid,
            result_data=result_data
        )


class DomainTransferHandler(ObjectCommandHandler):
    """
    Handle domain:transfer command.

    Calls epp_domain.domain_transfer() stored procedure.
    """

    command_name = "transfer"
    object_type = "domain"
    plsql_managed = True  # PL/SQL proc handles transaction logging

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:transfer command via PL/SQL."""
        cl_trid = command.client_transaction_id
        data = command.data

        domain_name = data.get("name")
        if not domain_name:
            raise CommandError(
                2003,
                "Required parameter missing",
                reason="Domain name required"
            )

        op = data.get("op", "request")
        if op not in ("request", "approve", "reject", "cancel", "query"):
            raise CommandError(
                2005,
                "Parameter value syntax error",
                reason=f"Invalid transfer operation: {op}"
            )

        auth_info = data.get("authInfo")
        period = data.get("period")
        unit = data.get("unit", "y")

        # Call ARI's stored procedure
        plsql = await get_plsql_caller()
        result = await plsql.domain_transfer(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            op=op,
            name=domain_name,
            period=period,
            period_unit=unit,
            auth_info=auth_info
        )

        response_code = result.get("response_code", 2400)

        if response_code >= 2000:
            raise _plsql_response_to_epp_error(
                response_code, result.get("response_message", "")
            )

        # Build transfer result data if transfer data is present
        if result.get("trStatus"):
            result_data = self.response_builder.build_domain_transfer_result(
                name=result.get("name", domain_name),
                tr_status=result.get("trStatus"),
                re_id=result.get("reID"),
                re_date=result.get("reDate"),
                ac_id=result.get("acID"),
                ac_date=result.get("acDate"),
                ex_date=result.get("exDate")
            )

            return self.success_response(
                cl_trid=cl_trid,
                code=response_code,
                message=result.get("response_message"),
                result_data=result_data
            )

        return self.success_response(
            cl_trid=cl_trid,
            code=response_code,
            message=result.get("response_message")
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
