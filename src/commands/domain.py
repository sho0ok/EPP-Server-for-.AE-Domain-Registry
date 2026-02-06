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
from src.database.repositories.extension_repo import get_extension_repo
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

        # Set audit log for transaction
        self.set_transaction_data(
            audit_log=f"Domain Check: {', '.join(names)}"
        )

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

        # Get extension data for the domain
        extension_repo = await get_extension_repo()
        domain_roid = domain.get("roid")
        extension_data = await extension_repo.get_domain_extension_data(domain_roid)

        # Format extension data for response
        extensions_response = None
        if extension_data:
            extensions_response = self._format_extension_data(extension_data)

        # Get Phase 7-11 extension data
        extension_elements = []

        # secDNS (DNSSEC) data - skip if table doesn't exist
        try:
            secdns_data = await extension_repo.get_domain_secdns_data(domain_roid)
            if secdns_data:
                secdns_elem = self.response_builder.build_secdns_info_data(secdns_data)
                if secdns_elem is not None:
                    extension_elements.append(secdns_elem)
        except Exception:
            pass  # DNSSEC tables may not exist

        # IDN data - skip if table doesn't exist
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
            pass  # IDN table may not exist

        # Variant data - skip if table doesn't exist
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
            pass  # Variant table may not exist

        # KV data - skip if table doesn't exist
        try:
            kv_data = await extension_repo.get_domain_kv_data(domain_roid)
            if kv_data:
                kv_elem = self.response_builder.build_kv_info_data(kv_data)
                if kv_elem is not None:
                    extension_elements.append(kv_elem)
        except Exception:
            pass  # KV table may not exist

        # Set audit log for transaction
        domain_roid = domain.get("roid")
        self.set_transaction_data(
            roid=domain_roid,
            audit_log=f"Domain Info: {domain_name}"
        )

        # Build response
        result_data = self.response_builder.build_domain_info_result(domain)

        # Combine old-style dict extensions with new XML element extensions
        final_extensions = None
        if extensions_response or extension_elements:
            from lxml import etree
            ext_container = etree.Element("{urn:ietf:params:xml:ns:epp-1.0}extension")

            # Add old-style extensions (converted from dict)
            if extensions_response:
                old_ext_xml = self.response_builder.build_extensions_response(extensions_response)
                if old_ext_xml is not None:
                    for child in old_ext_xml:
                        ext_container.append(child)

            # Add new Phase 7-11 extension elements
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
        """
        Format extension data for EPP response.

        Args:
            extension_data: Raw extension data from database

        Returns:
            Dict of {ext_name: {field_key: value}}
        """
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

        # Check zone status - 'N' means Not disabled (active), 'Y' means disabled
        zone_status = zone_config.get("ZON_STATUS")
        logger.debug(f"Zone {zone} config: {zone_config}")
        logger.info(f"Zone {zone} status: '{zone_status}' (type: {type(zone_status).__name__})")
        if zone_status not in ("N",):  # 'N' = Not disabled = Active
            raise CommandError(
                2306,
                "Parameter value policy error",
                reason=f"Zone {zone} is disabled (status: {zone_status})"
            )

        # Get zone ID for extension validation
        zone_id = zone_config.get("ZON_ID")

        # Validate zone extensions (for restricted zones like .co.ae, .gov.ae)
        extension_repo = await get_extension_repo()
        extension_data = self._extract_extension_data(command.extensions)

        if zone_id:
            extension_errors = await extension_repo.validate_extension_data(
                zone_id, extension_data
            )
            if extension_errors:
                raise CommandError(
                    2306,
                    "Parameter value policy error",
                    reason="; ".join(extension_errors)
                )

        # Get rate for billing (with rate_id for transaction logging)
        rate_info = await domain_repo.get_rate_with_id(zone, period, unit)
        if rate_info is None:
            raise CommandError(
                2306,
                "Parameter value policy error",
                reason=f"No rate found for {period}{unit} in zone {zone}"
            )
        rate = rate_info["amount"]
        rate_id = rate_info["rate_id"]

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

        # Create domain with billing in single atomic operation
        # Note: Debit happens first - if billing fails, no domain is created
        # If domain creation fails after billing, we should credit back (handled in except)
        new_balance = None
        try:
            # Debit account FIRST - ensures payment before domain creation
            new_balance = await account_repo.debit_balance(session.account_id, rate)
            billing_complete = True

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

                # Save extension data if present
                if extension_data and zone_id:
                    await self._save_extension_data(
                        extension_repo, roid, zone_id, extension_data
                    )

                # Save Phase 7-11 extension data
                await self._save_phase7_11_extensions(
                    extension_repo, roid, command.extensions
                )

            except Exception as e:
                # Domain creation failed after billing - refund
                logger.error(f"Domain creation failed, refunding account: {e}")
                await account_repo.credit_balance(session.account_id, rate)
                raise

        except ValueError as e:
            # Billing failure (insufficient funds)
            logger.error(f"Billing failed for domain {domain_name}: {e}")
            raise CommandError(
                2104,
                "Billing failure",
                reason=str(e)
            )
        except Exception as e:
            logger.error(f"Failed to create domain {domain_name}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        # Set transaction data for audit logging
        # This populates TRN_AMOUNT, TRN_BALANCE, TRN_ROID, TRN_AUDIT_LOG, TRN_RATE_ID, TRN_COMMENTS in TRANSACTIONS table
        self.set_transaction_data(
            amount=rate,
            balance=new_balance,
            roid=roid,
            audit_log=f"Domain Create: {domain_name}, Period: {period}{unit}, Registrant: {registrant_id}",
            rate_id=rate_id,
            comments=domain_name
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

    def _extract_extension_data(
        self, extensions: Dict[str, Any]
    ) -> Dict[str, Dict[str, str]]:
        """
        Extract extension field data from parsed extensions.

        Args:
            extensions: Parsed extensions dict

        Returns:
            Dict of {ext_name: {field_key: value}}
        """
        result = {}

        # AE Eligibility extension
        if "aeEligibility" in extensions:
            ae_ext = extensions["aeEligibility"]
            if "fields" in ae_ext:
                result["aeEligibility"] = ae_ext["fields"]

        # AE Domain extension
        if "aeDomain" in extensions:
            ae_dom = extensions["aeDomain"]
            if "fields" in ae_dom:
                result["aeDomain"] = ae_dom["fields"]

        # Generic extensions - extract data field
        for ext_name, ext_data in extensions.items():
            if ext_name not in result and isinstance(ext_data, dict):
                if "data" in ext_data:
                    result[ext_name] = ext_data["data"]
                elif "fields" in ext_data:
                    result[ext_name] = ext_data["fields"]

        return result

    async def _save_extension_data(
        self,
        extension_repo,
        domain_roid: str,
        zone_id: int,
        extension_data: Dict[str, Dict[str, str]]
    ):
        """
        Save extension field data for a domain.

        Args:
            extension_repo: Extension repository
            domain_roid: Domain ROID
            zone_id: Zone ID
            extension_data: Dict of {ext_name: {field_key: value}}
        """
        # Get field info for the zone
        field_info = await extension_repo.get_extension_field_info(zone_id)

        for ext_name, fields in extension_data.items():
            if ext_name not in field_info:
                continue

            ext_info = field_info[ext_name]
            zon_ext_id = ext_info.get("zon_ext_id")

            if not zon_ext_id:
                continue

            for field_key, value in fields.items():
                if field_key in ext_info.get("fields", {}):
                    field_config = ext_info["fields"][field_key]
                    field_id = field_config.get("field_id")

                    if field_id and value:
                        await extension_repo.save_domain_extension_data(
                            domain_roid=domain_roid,
                            zon_ext_id=zon_ext_id,
                            ext_item_field_id=field_id,
                            value=value
                        )

    async def _save_phase7_11_extensions(
        self,
        extension_repo,
        domain_roid: str,
        extensions: Dict[str, Any]
    ):
        """
        Save Phase 7-11 extension data for a domain.

        Args:
            extension_repo: Extension repository
            domain_roid: Domain ROID
            extensions: Parsed extensions dict
        """
        # Phase 7: secDNS (DNSSEC)
        if "secDNS" in extensions:
            secdns = extensions["secDNS"]
            if secdns.get("operation") == "create":
                await extension_repo.save_domain_secdns_data(
                    domain_roid=domain_roid,
                    ds_data=secdns.get("dsData"),
                    key_data=secdns.get("keyData"),
                    max_sig_life=secdns.get("maxSigLife")
                )

        # Phase 8: IDN
        if "idnadomain" in extensions:
            idn = extensions["idnadomain"]
            if idn.get("operation") == "create":
                await extension_repo.save_domain_idn_data(
                    domain_roid=domain_roid,
                    user_form=idn.get("userForm", ""),
                    language=idn.get("language", ""),
                    canonical_form=idn.get("canonicalForm")
                )

        # Phase 11: KV
        if "kv" in extensions:
            kv = extensions["kv"]
            if kv.get("operation") == "create":
                kvlists = kv.get("kvlists", [])
                if kvlists:
                    await extension_repo.save_domain_kv_data(
                        domain_roid=domain_roid,
                        kvlists=kvlists
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
            raise AuthorizationError("Only sponsoring registrar can update domain")

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

        # Normalize statuses to strings (handle both "status" and {"s": "status"} formats)
        add_statuses = [
            s.get("s") if isinstance(s, dict) else s for s in add_statuses_raw
        ]
        rem_statuses = [
            s.get("s") if isinstance(s, dict) else s for s in rem_statuses_raw
        ]

        registrant_id = chg_data.get("registrant")
        auth_info = chg_data.get("authInfo")

        # Validate auth info if being changed
        if auth_info:
            valid, error = validate_auth_info(auth_info)
            if not valid:
                raise CommandError(2005, "Parameter value syntax error", reason=f"AuthInfo: {error}")

        # Validate client can only modify client statuses
        for status in add_statuses + rem_statuses:
            if status and status.startswith("server"):
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
                add_statuses=[s for s in add_statuses if s] if add_statuses else None,
                rem_statuses=[s for s in rem_statuses if s] if rem_statuses else None
            )

            # Handle Phase 7-11 extension updates
            domain_roid = domain.get("roid")
            extension_repo = await get_extension_repo()
            await self._update_phase7_11_extensions(
                extension_repo, domain_roid, command.extensions
            )

        except Exception as e:
            logger.error(f"Failed to update domain {domain_name}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        # Build audit log with update details
        audit_parts = [f"Domain Update: {domain_name}"]
        if registrant_id:
            audit_parts.append(f"Registrant: {registrant_id}")
        if add_contacts:
            audit_parts.append(f"Add contacts: {add_contacts}")
        if rem_contacts:
            audit_parts.append(f"Rem contacts: {rem_contacts}")
        if add_nameservers:
            audit_parts.append(f"Add NS: {add_nameservers}")
        if rem_nameservers:
            audit_parts.append(f"Rem NS: {rem_nameservers}")
        if add_statuses:
            audit_parts.append(f"Add status: {[s for s in add_statuses if s]}")
        if rem_statuses:
            audit_parts.append(f"Rem status: {[s for s in rem_statuses if s]}")

        self.set_transaction_data(
            roid=domain_roid,
            audit_log=", ".join(audit_parts)
        )

        logger.info(f"Updated domain: {domain_name}")

        return self.success_response(cl_trid=cl_trid)

    async def _update_phase7_11_extensions(
        self,
        extension_repo,
        domain_roid: str,
        extensions: Dict[str, Any]
    ):
        """
        Update Phase 7-11 extension data for a domain.

        Args:
            extension_repo: Extension repository
            domain_roid: Domain ROID
            extensions: Parsed extensions dict
        """
        # Phase 7: secDNS update
        if "secDNS" in extensions:
            secdns = extensions["secDNS"]
            op = secdns.get("operation", "update")

            if op == "update":
                # Handle add
                add_data = secdns.get("add", {})
                if add_data:
                    await extension_repo.save_domain_secdns_data(
                        domain_roid=domain_roid,
                        ds_data=add_data.get("dsData"),
                        key_data=add_data.get("keyData")
                    )

                # Handle rem
                rem_data = secdns.get("rem", {})
                if rem_data:
                    await extension_repo.delete_domain_secdns_data(
                        domain_roid=domain_roid,
                        ds_data=rem_data.get("dsData"),
                        key_data=rem_data.get("keyData"),
                        remove_all=rem_data.get("all", False)
                    )

                # Handle chg (maxSigLife)
                chg_data = secdns.get("chg", {})
                if chg_data.get("maxSigLife"):
                    await extension_repo.save_domain_secdns_data(
                        domain_roid=domain_roid,
                        max_sig_life=chg_data["maxSigLife"]
                    )

        # Phase 9: Variant update
        if "variant" in extensions:
            variant = extensions["variant"]
            op = variant.get("operation", "update")

            if op == "update":
                # Handle add
                add_variants = variant.get("add", [])
                if add_variants:
                    await extension_repo.add_domain_variants(domain_roid, add_variants)

                # Handle rem
                rem_variants = variant.get("rem", [])
                if rem_variants:
                    await extension_repo.remove_domain_variants(domain_roid, rem_variants)

        # Phase 10: Sync update (expiry date sync)
        if "sync" in extensions:
            sync = extensions["sync"]
            # The sync extension updates expiry date - this would be handled
            # separately by the domain_repo, but we capture the parsed data here
            pass  # Expiry date update handled via domain_repo

        # Phase 11: KV update
        if "kv" in extensions:
            kv = extensions["kv"]
            if kv.get("operation") == "update":
                kvlists = kv.get("kvlists", [])
                if kvlists:
                    await extension_repo.save_domain_kv_data(
                        domain_roid=domain_roid,
                        kvlists=kvlists
                    )


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
            raise AuthorizationError("Only sponsoring registrar can delete domain")

        # Perform delete (marks as pendingDelete)
        domain_roid = domain.get("roid")
        try:
            await domain_repo.delete(domain_name, immediate=False)
        except Exception as e:
            logger.error(f"Failed to delete domain {domain_name}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        # Set audit log for transaction
        self.set_transaction_data(
            roid=domain_roid,
            audit_log=f"Domain Delete: {domain_name}"
        )

        logger.info(f"Marked domain for deletion: {domain_name}")

        # Return 1001 for pending action
        return self.success_response(
            cl_trid=cl_trid,
            code=1001,
            message="Command completed successfully; action pending"
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
            raise AuthorizationError("Only sponsoring registrar can renew domain")

        # Get period (optional, default 1 year)
        period = data.get("period", 1)
        unit = data.get("unit", "y")

        # Validate period
        validator = get_validator()
        valid, error = validator.validate_period(period, unit)
        if not valid:
            raise CommandError(2005, "Parameter value syntax error", reason=error)

        # Get zone and rate (with rate_id for transaction logging)
        zone = domain.get("_zone")
        rate_info = await domain_repo.get_rate_with_id(zone, period, unit)
        if rate_info is None:
            raise CommandError(
                2306,
                "Parameter value policy error",
                reason=f"No rate found for {period}{unit} in zone {zone}"
            )
        rate = rate_info["amount"]
        rate_id = rate_info["rate_id"]

        # Check account balance
        account_repo = await get_account_repo()
        balance = await account_repo.get_balance(session.account_id)
        if balance < rate:
            raise CommandError(
                2104,
                "Billing failure",
                reason="Insufficient balance"
            )

        # Perform renewal with billing
        new_balance = None
        domain_roid = domain.get("roid")
        try:
            # Debit account FIRST
            new_balance = await account_repo.debit_balance(session.account_id, rate)

            try:
                result = await domain_repo.renew(
                    domain_name=domain_name,
                    user_id=session.user_id,
                    current_expiry=current_expiry,
                    period=period,
                    unit=unit
                )
            except Exception as e:
                # Renewal failed after billing - refund
                logger.error(f"Domain renewal failed, refunding account: {e}")
                await account_repo.credit_balance(session.account_id, rate)
                raise

        except ValueError as e:
            # Billing failure (insufficient funds)
            logger.error(f"Billing failed for domain renewal {domain_name}: {e}")
            raise CommandError(
                2104,
                "Billing failure",
                reason=str(e)
            )
        except Exception as e:
            logger.error(f"Failed to renew domain {domain_name}: {e}")
            raise CommandError(
                2400,
                "Command failed",
                reason=str(e)
            )

        # Set transaction data for audit logging
        # This populates TRN_AMOUNT, TRN_BALANCE, TRN_ROID, TRN_AUDIT_LOG, TRN_RATE_ID, TRN_COMMENTS in TRANSACTIONS table
        self.set_transaction_data(
            amount=rate,
            balance=new_balance,
            roid=domain_roid,
            audit_log=f"Domain Renew: {domain_name}, Period: {period}{unit}, New Expiry: {result.get('exDate')}",
            rate_id=rate_id,
            comments=domain_name
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

            # Set audit log for transfer query
            domain_roid = domain.get("roid")
            self.set_transaction_data(
                roid=domain_roid,
                audit_log=f"Domain Transfer Query: {domain_name}"
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

            # Set audit log for transfer request
            domain_roid = domain.get("roid")
            self.set_transaction_data(
                roid=domain_roid,
                audit_log=f"Domain Transfer Request: {domain_name}, Period: {period}{unit}"
            )

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
                message="Command completed successfully; action pending",
                result_data=result_data
            )

        elif op == "approve":
            # Approve transfer - must be current sponsor
            if sponsoring_account != session.account_id:
                raise AuthorizationError("Only current sponsoring registrar can approve transfer")

            domain_roid = domain.get("roid")
            try:
                result = await domain_repo.approve_transfer(domain_name, session.user_id)
            except Exception as e:
                logger.error(f"Failed to approve transfer for {domain_name}: {e}")
                raise CommandError(2400, "Command failed", reason=str(e))

            # Set audit log for transfer approve
            self.set_transaction_data(
                roid=domain_roid,
                audit_log=f"Domain Transfer Approve: {domain_name}"
            )

            logger.info(f"Transfer approved for domain: {domain_name}")
            return self.success_response(cl_trid=cl_trid)

        elif op == "reject":
            # Reject transfer - must be current sponsor
            if sponsoring_account != session.account_id:
                raise AuthorizationError("Only current sponsoring registrar can reject transfer")

            domain_roid = domain.get("roid")
            try:
                result = await domain_repo.reject_transfer(domain_name, session.user_id)
            except Exception as e:
                logger.error(f"Failed to reject transfer for {domain_name}: {e}")
                raise CommandError(2400, "Command failed", reason=str(e))

            # Set audit log for transfer reject
            self.set_transaction_data(
                roid=domain_roid,
                audit_log=f"Domain Transfer Reject: {domain_name}"
            )

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
            domain_roid = domain.get("roid")

            try:
                result = await domain_repo.cancel_transfer(domain_name, session.user_id)
            except Exception as e:
                logger.error(f"Failed to cancel transfer for {domain_name}: {e}")
                raise CommandError(2400, "Command failed", reason=str(e))

            # Set audit log for transfer cancel
            self.set_transaction_data(
                roid=domain_roid,
                audit_log=f"Domain Transfer Cancel: {domain_name}"
            )

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
