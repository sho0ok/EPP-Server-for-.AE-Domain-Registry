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
)
from src.core.session_manager import SessionInfo
from src.core.xml_processor import EPPCommand
from src.database.plsql_caller import get_plsql_caller
from src.database.repositories.domain_repo import get_domain_repo
from src.utils.password_utils import generate_auth_info, validate_auth_info
from src.commands.extensions.ar_extension import (
    ArUndeleteHandler,
    ArUnrenewHandler,
    ArPolicyDeleteHandler,
)
from src.commands.extensions.ae_extension import AeDomainTransferRegistrantHandler
from src.commands.extensions.au_extension import AuDomainTransferRegistrantHandler

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

    Calls epp_domain.domain_info() stored procedure.
    PL/SQL handles authorization, auth info visibility, hosts filtering,
    and returns all data including extensions, DNSSEC, and IDN.
    """

    command_name = "info"
    object_type = "domain"
    plsql_managed = True  # PL/SQL proc handles transaction logging

    async def handle(
        self,
        command: EPPCommand,
        session: SessionInfo
    ) -> bytes:
        """Process domain:info command via PL/SQL."""
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

        # Call ARI's stored procedure - handles auth, hosts filtering, everything
        plsql = await get_plsql_caller()
        result = await plsql.domain_info(
            connection_id=session.connection_id,
            session_id=session.session_id,
            cltrid=cl_trid,
            name=domain_name,
            hosts=hosts_filter,
            auth_info=auth_info
        )

        response_code = result.get("response_code", 2400)

        if response_code >= 2000:
            return self.response_builder.build_error(
                code=response_code,
                message=result.get("response_message", "Command failed"),
                cl_trid=cl_trid,
                sv_trid=result.get("sv_trid")
            )

        # Build domain dict for build_domain_info_result()
        domain = {
            "name": result.get("name", domain_name),
            "roid": result.get("roid", ""),
            "statuses": result.get("statuses", []),
            "registrant": result.get("registrant"),
            "contacts": result.get("contacts", []),
            "nameservers": result.get("nameservers", []),
            "hosts": result.get("hosts", []),
            "clID": result.get("clID", ""),
            "crID": result.get("crID"),
            "crDate": result.get("crDate"),
            "upID": result.get("upID"),
            "upDate": result.get("upDate"),
            "exDate": result.get("exDate"),
            "trDate": result.get("trDate"),
            "authInfo": result.get("authInfo"),
        }

        result_data = self.response_builder.build_domain_info_result(domain)

        # Build extension elements from PL/SQL result
        extension_elements = []

        # TLD-specific extensions (aeext, auext, etc.) from PL/SQL current_values
        for ext in result.get("extensions", []):
            ext_name = ext.get("extension", "")
            cv = ext.get("current_values", {})
            if not cv:
                continue

            if ext_name == "aeext" or ext_name == "aeEligibility":
                ae_elem = self.response_builder.build_ae_info_data(
                    registrant_name=cv.get("registrantName", ""),
                    eligibility_type=cv.get("eligibilityType", ""),
                    registrant_id=cv.get("registrantID"),
                    registrant_id_type=cv.get("registrantIDType"),
                    eligibility_name=cv.get("eligibilityName"),
                    eligibility_id=cv.get("eligibilityID"),
                    eligibility_id_type=cv.get("eligibilityIDType"),
                    policy_reason=int(cv["policyReason"]) if cv.get("policyReason") else None,
                )
                extension_elements.append(ae_elem)
            elif ext_name == "auext":
                au_elem = self.response_builder.build_au_info_data(
                    registrant_name=cv.get("registrantName", ""),
                    eligibility_type=cv.get("eligibilityType", ""),
                    policy_reason=int(cv.get("policyReason", 1)),
                    registrant_id=cv.get("registrantID"),
                    registrant_id_type=cv.get("registrantIDType"),
                    eligibility_name=cv.get("eligibilityName"),
                    eligibility_id=cv.get("eligibilityID"),
                    eligibility_id_type=cv.get("eligibilityIDType"),
                )
                extension_elements.append(au_elem)
            else:
                # Generic extension — build as KV list
                items = [{"key": k, "value": v} for k, v in cv.items()]
                if items:
                    kv_elem = self.response_builder.build_kv_info_data(
                        [{"name": ext_name, "items": items}]
                    )
                    extension_elements.append(kv_elem)

        # DNSSEC extension
        ds_data = result.get("dnssec_ds", [])
        key_data = result.get("dnssec_keys", [])
        if ds_data or key_data:
            # Map PL/SQL field names to response builder field names
            mapped_ds = []
            for ds in ds_data:
                entry = {
                    "keyTag": ds.get("keyTag", 0),
                    "alg": ds.get("algorithm", 0),
                    "digestType": ds.get("digestType", 0),
                    "digest": ds.get("digest", ""),
                }
                if ds.get("keyData"):
                    kd = ds["keyData"]
                    entry["keyData"] = {
                        "flags": kd.get("flags", 0),
                        "protocol": kd.get("protocol", 3),
                        "alg": kd.get("algorithm", 0),
                        "pubKey": kd.get("publicKey", ""),
                    }
                mapped_ds.append(entry)

            mapped_keys = []
            for kd in key_data:
                mapped_keys.append({
                    "flags": kd.get("flags", 0),
                    "protocol": kd.get("protocol", 3),
                    "alg": kd.get("algorithm", 0),
                    "pubKey": kd.get("publicKey", ""),
                })

            secdns_elem = self.response_builder.build_secdns_info_data(
                ds_data=mapped_ds or None,
                key_data=mapped_keys or None
            )
            if secdns_elem is not None:
                extension_elements.append(secdns_elem)

        # IDN extension
        idn_userform = result.get("idn_userform")
        idn_language = result.get("idn_language")
        idn_canonical = result.get("idn_canonical")
        if idn_userform and idn_language:
            idn_elem = self.response_builder.build_idn_info_data(
                user_form=idn_userform,
                language=idn_language,
                canonical_form=idn_canonical or domain_name
            )
            if idn_elem is not None:
                extension_elements.append(idn_elem)

        logger.info(f"Domain info via PL/SQL: {domain_name}")

        # For single or no extensions, use build_response directly
        # For multiple, pass first and append rest to avoid double nesting
        if len(extension_elements) == 0:
            return self.response_builder.build_response(
                code=response_code,
                message=result.get("response_message"),
                cl_trid=cl_trid,
                sv_trid=result.get("sv_trid"),
                result_data=result_data
            )
        elif len(extension_elements) == 1:
            return self.response_builder.build_response(
                code=response_code,
                message=result.get("response_message"),
                cl_trid=cl_trid,
                sv_trid=result.get("sv_trid"),
                result_data=result_data,
                extensions=extension_elements[0]
            )
        else:
            # Multiple extensions: build response with first, then append rest
            from lxml import etree
            response_bytes = self.response_builder.build_response(
                code=response_code,
                message=result.get("response_message"),
                cl_trid=cl_trid,
                sv_trid=result.get("sv_trid"),
                result_data=result_data,
                extensions=extension_elements[0]
            )
            # Parse, add remaining extension elements, re-serialize
            root = etree.fromstring(response_bytes)
            ext_elem = root.find(".//{urn:ietf:params:xml:ns:epp-1.0}extension")
            if ext_elem is None:
                ext_elem = root.find(".//extension")
            if ext_elem is not None:
                for elem in extension_elements[1:]:
                    ext_elem.append(elem)
            return etree.tostring(
                root, xml_declaration=True, encoding="UTF-8", pretty_print=False
            )


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

        # IDN language and userform
        idna_language = None
        idn_userform = None
        if "idnadomain" in command.extensions:
            idn = command.extensions["idnadomain"]
            idna_language = idn.get("language")
            idn_userform = idn.get("userForm")

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
            userform=idn_userform or domain_name,
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

        # AE Eligibility extension (DB extension code is 'ae')
        # For domain create: data goes in current_values, new_values=None, reason='Domain Create'
        if "aeEligibility" in extensions:
            ae_ext = extensions["aeEligibility"]
            fields = ae_ext.get("fields", {})
            if fields:
                result.append({
                    "extension": "ae",
                    "current_values": fields,
                    "new_values": None,
                    "reason": "Domain Create"
                })

        # AE Domain extension
        if "aeDomain" in extensions:
            ae_dom = extensions["aeDomain"]
            fields = ae_dom.get("fields", {})
            if fields:
                result.append({
                    "extension": "aeDomain",
                    "current_values": fields,
                    "new_values": None,
                    "reason": "Domain Create"
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
                        "current_values": fields,
                        "new_values": None,
                        "reason": "Domain Create"
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

        # Normalize statuses - preserve full dict with s, lang, reason
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
    # AR extension protocol commands
    "ar_undelete": ArUndeleteHandler,
    "ar_unrenew": ArUnrenewHandler,
    "ar_policy_delete": ArPolicyDeleteHandler,
    # AE extension protocol commands
    "ae_transfer_registrant": AeDomainTransferRegistrantHandler,
    # AU extension protocol commands
    "au_transfer_registrant": AuDomainTransferRegistrantHandler,
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
