"""
EPP XML Builder

Builds EPP XML commands per RFC 5730-5733.
"""

import secrets
import string
from datetime import datetime
from typing import Any, Dict, List, Optional

from lxml import etree

from epp_client.models import (
    DomainCreate,
    DomainUpdate,
    DomainContact,
    ContactCreate,
    ContactUpdate,
    PostalInfo,
    HostCreate,
    HostUpdate,
    HostAddress,
    StatusValue,
)

# EPP Namespaces
NS = {
    "epp": "urn:ietf:params:xml:ns:epp-1.0",
    "domain": "urn:ietf:params:xml:ns:domain-1.0",
    "contact": "urn:ietf:params:xml:ns:contact-1.0",
    "host": "urn:ietf:params:xml:ns:host-1.0",
}

# Namespace URIs
EPP_NS = "urn:ietf:params:xml:ns:epp-1.0"
DOMAIN_NS = "urn:ietf:params:xml:ns:domain-1.0"
CONTACT_NS = "urn:ietf:params:xml:ns:contact-1.0"
HOST_NS = "urn:ietf:params:xml:ns:host-1.0"


def _generate_cl_trid() -> str:
    """Generate client transaction ID."""
    chars = string.ascii_uppercase + string.digits
    random_part = ''.join(secrets.choice(chars) for _ in range(8))
    return f"CLI-{random_part}"


def _generate_auth_info(length: int = 16) -> str:
    """Generate random auth info."""
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(secrets.choice(chars) for _ in range(length))


def _create_epp_root() -> etree._Element:
    """Create EPP root element with namespaces."""
    nsmap = {
        None: EPP_NS,
        "domain": DOMAIN_NS,
        "contact": CONTACT_NS,
        "host": HOST_NS,
    }
    return etree.Element("{%s}epp" % EPP_NS, nsmap=nsmap)


def _add_cl_trid(command: etree._Element, cl_trid: str = None) -> None:
    """Add client transaction ID to command."""
    if cl_trid is None:
        cl_trid = _generate_cl_trid()
    etree.SubElement(command, "{%s}clTRID" % EPP_NS).text = cl_trid


# AE Eligibility namespace
AE_ELIGIBILITY_NS = "urn:aeda:params:xml:ns:aeEligibility-1.0"


def _add_ae_eligibility_extension(command: etree._Element, eligibility) -> None:
    """Add AE Eligibility extension to command."""
    extension = etree.SubElement(command, "{%s}extension" % EPP_NS)

    ae_create = etree.Element(
        "{%s}create" % AE_ELIGIBILITY_NS,
        nsmap={"aeEligibility": AE_ELIGIBILITY_NS}
    )

    # Add eligibility fields
    if eligibility.eligibility_type:
        etree.SubElement(ae_create, "{%s}eligibilityType" % AE_ELIGIBILITY_NS).text = eligibility.eligibility_type

    if eligibility.eligibility_name:
        etree.SubElement(ae_create, "{%s}eligibilityName" % AE_ELIGIBILITY_NS).text = eligibility.eligibility_name

    if eligibility.eligibility_id:
        etree.SubElement(ae_create, "{%s}eligibilityID" % AE_ELIGIBILITY_NS).text = eligibility.eligibility_id

    if eligibility.eligibility_id_type:
        etree.SubElement(ae_create, "{%s}eligibilityIDType" % AE_ELIGIBILITY_NS).text = eligibility.eligibility_id_type

    if eligibility.policy_reason is not None:
        etree.SubElement(ae_create, "{%s}policyReason" % AE_ELIGIBILITY_NS).text = str(eligibility.policy_reason)

    if eligibility.registrant_id:
        etree.SubElement(ae_create, "{%s}registrantID" % AE_ELIGIBILITY_NS).text = eligibility.registrant_id

    if eligibility.registrant_id_type:
        etree.SubElement(ae_create, "{%s}registrantIDType" % AE_ELIGIBILITY_NS).text = eligibility.registrant_id_type

    if eligibility.registrant_name:
        etree.SubElement(ae_create, "{%s}registrantName" % AE_ELIGIBILITY_NS).text = eligibility.registrant_name

    extension.append(ae_create)


def _to_bytes(root: etree._Element) -> bytes:
    """Convert element tree to XML bytes."""
    return etree.tostring(
        root,
        xml_declaration=True,
        encoding="UTF-8",
        pretty_print=False
    )


class XMLBuilder:
    """
    Builds EPP XML commands.

    All methods are static and return XML bytes ready to send.
    """

    # =========================================================================
    # Session Commands
    # =========================================================================

    @staticmethod
    def build_hello() -> bytes:
        """Build hello command."""
        root = _create_epp_root()
        etree.SubElement(root, "{%s}hello" % EPP_NS)
        return _to_bytes(root)

    @staticmethod
    def build_login(
        client_id: str,
        password: str,
        new_password: str = None,
        version: str = "1.0",
        lang: str = "en",
        obj_uris: List[str] = None,
        ext_uris: List[str] = None,
        cl_trid: str = None,
    ) -> bytes:
        """
        Build login command.

        Args:
            client_id: Client identifier
            password: Password
            new_password: New password (optional)
            version: EPP version
            lang: Language
            obj_uris: Object URIs to use
            ext_uris: Extension URIs to use
            cl_trid: Client transaction ID
        """
        if obj_uris is None:
            obj_uris = [DOMAIN_NS, CONTACT_NS, HOST_NS]

        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        login = etree.SubElement(command, "{%s}login" % EPP_NS)

        etree.SubElement(login, "{%s}clID" % EPP_NS).text = client_id
        etree.SubElement(login, "{%s}pw" % EPP_NS).text = password

        if new_password:
            etree.SubElement(login, "{%s}newPW" % EPP_NS).text = new_password

        options = etree.SubElement(login, "{%s}options" % EPP_NS)
        etree.SubElement(options, "{%s}version" % EPP_NS).text = version
        etree.SubElement(options, "{%s}lang" % EPP_NS).text = lang

        svcs = etree.SubElement(login, "{%s}svcs" % EPP_NS)
        for uri in obj_uris:
            etree.SubElement(svcs, "{%s}objURI" % EPP_NS).text = uri

        if ext_uris:
            svc_ext = etree.SubElement(svcs, "{%s}svcExtension" % EPP_NS)
            for uri in ext_uris:
                etree.SubElement(svc_ext, "{%s}extURI" % EPP_NS).text = uri

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_logout(cl_trid: str = None) -> bytes:
        """Build logout command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        etree.SubElement(command, "{%s}logout" % EPP_NS)
        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_poll_request(cl_trid: str = None) -> bytes:
        """Build poll request command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)

        poll = etree.SubElement(command, "{%s}poll" % EPP_NS)
        poll.set("op", "req")

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_poll_ack(msg_id: str, cl_trid: str = None) -> bytes:
        """Build poll acknowledge command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)

        poll = etree.SubElement(command, "{%s}poll" % EPP_NS)
        poll.set("op", "ack")
        poll.set("msgID", msg_id)

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # Domain Commands
    # =========================================================================

    @staticmethod
    def build_domain_check(names: List[str], cl_trid: str = None) -> bytes:
        """Build domain:check command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        check = etree.SubElement(command, "{%s}check" % EPP_NS)

        domain_check = etree.SubElement(check, "{%s}check" % DOMAIN_NS)
        for name in names:
            etree.SubElement(domain_check, "{%s}name" % DOMAIN_NS).text = name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_info(
        name: str,
        auth_info: str = None,
        hosts: str = "all",
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:info command.

        Args:
            name: Domain name
            auth_info: Auth info (for full details)
            hosts: Hosts to return - "all", "del", "sub", "none"
            cl_trid: Client transaction ID
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        info = etree.SubElement(command, "{%s}info" % EPP_NS)

        domain_info = etree.SubElement(info, "{%s}info" % DOMAIN_NS)
        name_elem = etree.SubElement(domain_info, "{%s}name" % DOMAIN_NS)
        name_elem.text = name
        name_elem.set("hosts", hosts)

        if auth_info:
            auth = etree.SubElement(domain_info, "{%s}authInfo" % DOMAIN_NS)
            etree.SubElement(auth, "{%s}pw" % DOMAIN_NS).text = auth_info

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_create(create_data: DomainCreate, cl_trid: str = None) -> bytes:
        """Build domain:create command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        create = etree.SubElement(command, "{%s}create" % EPP_NS)

        domain_create = etree.SubElement(create, "{%s}create" % DOMAIN_NS)
        etree.SubElement(domain_create, "{%s}name" % DOMAIN_NS).text = create_data.name

        period = etree.SubElement(domain_create, "{%s}period" % DOMAIN_NS)
        period.text = str(create_data.period)
        period.set("unit", create_data.period_unit)

        # Nameservers
        if create_data.nameservers:
            ns = etree.SubElement(domain_create, "{%s}ns" % DOMAIN_NS)
            for host in create_data.nameservers:
                etree.SubElement(ns, "{%s}hostObj" % DOMAIN_NS).text = host

        # Registrant
        etree.SubElement(domain_create, "{%s}registrant" % DOMAIN_NS).text = create_data.registrant

        # Contacts
        if create_data.admin:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = create_data.admin
            c.set("type", "admin")
        if create_data.tech:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = create_data.tech
            c.set("type", "tech")
        if create_data.billing:
            c = etree.SubElement(domain_create, "{%s}contact" % DOMAIN_NS)
            c.text = create_data.billing
            c.set("type", "billing")

        # Auth info
        auth_info = create_data.auth_info or _generate_auth_info()
        auth = etree.SubElement(domain_create, "{%s}authInfo" % DOMAIN_NS)
        etree.SubElement(auth, "{%s}pw" % DOMAIN_NS).text = auth_info

        _add_cl_trid(command, cl_trid)

        # Add AE Eligibility extension if present
        if create_data.ae_eligibility:
            _add_ae_eligibility_extension(command, create_data.ae_eligibility)

        return _to_bytes(root)

    @staticmethod
    def build_domain_delete(name: str, cl_trid: str = None) -> bytes:
        """Build domain:delete command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        delete = etree.SubElement(command, "{%s}delete" % EPP_NS)

        domain_delete = etree.SubElement(delete, "{%s}delete" % DOMAIN_NS)
        etree.SubElement(domain_delete, "{%s}name" % DOMAIN_NS).text = name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_renew(
        name: str,
        cur_exp_date: str,
        period: int = 1,
        period_unit: str = "y",
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:renew command.

        Args:
            name: Domain name
            cur_exp_date: Current expiry date (YYYY-MM-DD)
            period: Renewal period
            period_unit: Period unit (y=year, m=month)
            cl_trid: Client transaction ID
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        renew = etree.SubElement(command, "{%s}renew" % EPP_NS)

        domain_renew = etree.SubElement(renew, "{%s}renew" % DOMAIN_NS)
        etree.SubElement(domain_renew, "{%s}name" % DOMAIN_NS).text = name
        etree.SubElement(domain_renew, "{%s}curExpDate" % DOMAIN_NS).text = cur_exp_date

        period_elem = etree.SubElement(domain_renew, "{%s}period" % DOMAIN_NS)
        period_elem.text = str(period)
        period_elem.set("unit", period_unit)

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_transfer(
        name: str,
        op: str = "request",
        auth_info: str = None,
        period: int = None,
        period_unit: str = "y",
        cl_trid: str = None,
    ) -> bytes:
        """
        Build domain:transfer command.

        Args:
            name: Domain name
            op: Operation - "request", "approve", "reject", "cancel", "query"
            auth_info: Auth info (required for request)
            period: Renewal period on transfer (optional)
            period_unit: Period unit (y=year, m=month)
            cl_trid: Client transaction ID
        """
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        transfer = etree.SubElement(command, "{%s}transfer" % EPP_NS)
        transfer.set("op", op)

        domain_transfer = etree.SubElement(transfer, "{%s}transfer" % DOMAIN_NS)
        etree.SubElement(domain_transfer, "{%s}name" % DOMAIN_NS).text = name

        if period:
            period_elem = etree.SubElement(domain_transfer, "{%s}period" % DOMAIN_NS)
            period_elem.text = str(period)
            period_elem.set("unit", period_unit)

        if auth_info:
            auth = etree.SubElement(domain_transfer, "{%s}authInfo" % DOMAIN_NS)
            etree.SubElement(auth, "{%s}pw" % DOMAIN_NS).text = auth_info

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_domain_update(update_data: DomainUpdate, cl_trid: str = None) -> bytes:
        """Build domain:update command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        update_cmd = etree.SubElement(command, "{%s}update" % EPP_NS)

        domain_update = etree.SubElement(update_cmd, "{%s}update" % DOMAIN_NS)
        etree.SubElement(domain_update, "{%s}name" % DOMAIN_NS).text = update_data.name

        # Add section
        if update_data.add_ns or update_data.add_contacts or update_data.add_status:
            add = etree.SubElement(domain_update, "{%s}add" % DOMAIN_NS)
            if update_data.add_ns:
                ns = etree.SubElement(add, "{%s}ns" % DOMAIN_NS)
                for host in update_data.add_ns:
                    etree.SubElement(ns, "{%s}hostObj" % DOMAIN_NS).text = host
            for contact in update_data.add_contacts:
                c = etree.SubElement(add, "{%s}contact" % DOMAIN_NS)
                c.text = contact.id
                c.set("type", contact.type)
            for status in update_data.add_status:
                s = etree.SubElement(add, "{%s}status" % DOMAIN_NS)
                if isinstance(status, StatusValue):
                    s.set("s", status.status)
                    if status.reason:
                        s.set("lang", status.lang)
                        s.text = status.reason
                else:
                    s.set("s", status)

        # Remove section
        if update_data.rem_ns or update_data.rem_contacts or update_data.rem_status:
            rem = etree.SubElement(domain_update, "{%s}rem" % DOMAIN_NS)
            if update_data.rem_ns:
                ns = etree.SubElement(rem, "{%s}ns" % DOMAIN_NS)
                for host in update_data.rem_ns:
                    etree.SubElement(ns, "{%s}hostObj" % DOMAIN_NS).text = host
            for contact in update_data.rem_contacts:
                c = etree.SubElement(rem, "{%s}contact" % DOMAIN_NS)
                c.text = contact.id
                c.set("type", contact.type)
            for status in update_data.rem_status:
                s = etree.SubElement(rem, "{%s}status" % DOMAIN_NS)
                if isinstance(status, StatusValue):
                    s.set("s", status.status)
                else:
                    s.set("s", status)

        # Change section
        if update_data.new_registrant or update_data.new_auth_info:
            chg = etree.SubElement(domain_update, "{%s}chg" % DOMAIN_NS)
            if update_data.new_registrant:
                etree.SubElement(chg, "{%s}registrant" % DOMAIN_NS).text = update_data.new_registrant
            if update_data.new_auth_info:
                auth = etree.SubElement(chg, "{%s}authInfo" % DOMAIN_NS)
                etree.SubElement(auth, "{%s}pw" % DOMAIN_NS).text = update_data.new_auth_info

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # Contact Commands
    # =========================================================================

    @staticmethod
    def build_contact_check(ids: List[str], cl_trid: str = None) -> bytes:
        """Build contact:check command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        check = etree.SubElement(command, "{%s}check" % EPP_NS)

        contact_check = etree.SubElement(check, "{%s}check" % CONTACT_NS)
        for id in ids:
            etree.SubElement(contact_check, "{%s}id" % CONTACT_NS).text = id

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_contact_info(
        id: str,
        auth_info: str = None,
        cl_trid: str = None,
    ) -> bytes:
        """Build contact:info command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        info = etree.SubElement(command, "{%s}info" % EPP_NS)

        contact_info = etree.SubElement(info, "{%s}info" % CONTACT_NS)
        etree.SubElement(contact_info, "{%s}id" % CONTACT_NS).text = id

        if auth_info:
            auth = etree.SubElement(contact_info, "{%s}authInfo" % CONTACT_NS)
            etree.SubElement(auth, "{%s}pw" % CONTACT_NS).text = auth_info

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_contact_create(create_data: ContactCreate, cl_trid: str = None) -> bytes:
        """Build contact:create command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        create = etree.SubElement(command, "{%s}create" % EPP_NS)

        contact_create = etree.SubElement(create, "{%s}create" % CONTACT_NS)
        etree.SubElement(contact_create, "{%s}id" % CONTACT_NS).text = create_data.id

        # Postal info
        postal = etree.SubElement(contact_create, "{%s}postalInfo" % CONTACT_NS)
        postal.set("type", create_data.postal_info.type)
        etree.SubElement(postal, "{%s}name" % CONTACT_NS).text = create_data.postal_info.name
        if create_data.postal_info.org:
            etree.SubElement(postal, "{%s}org" % CONTACT_NS).text = create_data.postal_info.org
        addr = etree.SubElement(postal, "{%s}addr" % CONTACT_NS)
        for street in create_data.postal_info.street:
            etree.SubElement(addr, "{%s}street" % CONTACT_NS).text = street
        etree.SubElement(addr, "{%s}city" % CONTACT_NS).text = create_data.postal_info.city
        if create_data.postal_info.sp:
            etree.SubElement(addr, "{%s}sp" % CONTACT_NS).text = create_data.postal_info.sp
        if create_data.postal_info.pc:
            etree.SubElement(addr, "{%s}pc" % CONTACT_NS).text = create_data.postal_info.pc
        etree.SubElement(addr, "{%s}cc" % CONTACT_NS).text = create_data.postal_info.cc

        # Voice
        if create_data.voice:
            voice = etree.SubElement(contact_create, "{%s}voice" % CONTACT_NS)
            voice.text = create_data.voice
            if create_data.voice_ext:
                voice.set("x", create_data.voice_ext)

        # Fax
        if create_data.fax:
            fax = etree.SubElement(contact_create, "{%s}fax" % CONTACT_NS)
            fax.text = create_data.fax
            if create_data.fax_ext:
                fax.set("x", create_data.fax_ext)

        # Email
        etree.SubElement(contact_create, "{%s}email" % CONTACT_NS).text = create_data.email

        # Auth info
        auth_info = create_data.auth_info or _generate_auth_info()
        auth = etree.SubElement(contact_create, "{%s}authInfo" % CONTACT_NS)
        etree.SubElement(auth, "{%s}pw" % CONTACT_NS).text = auth_info

        # Disclose
        if create_data.disclose:
            disclose = etree.SubElement(contact_create, "{%s}disclose" % CONTACT_NS)
            disclose.set("flag", "1" if any(create_data.disclose.values()) else "0")
            for field, show in create_data.disclose.items():
                if show:
                    etree.SubElement(disclose, "{%s}%s" % (CONTACT_NS, field))

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_contact_delete(id: str, cl_trid: str = None) -> bytes:
        """Build contact:delete command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        delete = etree.SubElement(command, "{%s}delete" % EPP_NS)

        contact_delete = etree.SubElement(delete, "{%s}delete" % CONTACT_NS)
        etree.SubElement(contact_delete, "{%s}id" % CONTACT_NS).text = id

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_contact_update(update_data: ContactUpdate, cl_trid: str = None) -> bytes:
        """Build contact:update command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        update_cmd = etree.SubElement(command, "{%s}update" % EPP_NS)

        contact_update = etree.SubElement(update_cmd, "{%s}update" % CONTACT_NS)
        etree.SubElement(contact_update, "{%s}id" % CONTACT_NS).text = update_data.id

        # Add section
        if update_data.add_status:
            add = etree.SubElement(contact_update, "{%s}add" % CONTACT_NS)
            for status in update_data.add_status:
                s = etree.SubElement(add, "{%s}status" % CONTACT_NS)
                s.set("s", status)

        # Remove section
        if update_data.rem_status:
            rem = etree.SubElement(contact_update, "{%s}rem" % CONTACT_NS)
            for status in update_data.rem_status:
                s = etree.SubElement(rem, "{%s}status" % CONTACT_NS)
                s.set("s", status)

        # Change section
        if update_data.new_postal_info or update_data.new_voice or update_data.new_fax or update_data.new_email or update_data.new_auth_info:
            chg = etree.SubElement(contact_update, "{%s}chg" % CONTACT_NS)

            if update_data.new_postal_info:
                postal = etree.SubElement(chg, "{%s}postalInfo" % CONTACT_NS)
                postal.set("type", update_data.new_postal_info.type)
                etree.SubElement(postal, "{%s}name" % CONTACT_NS).text = update_data.new_postal_info.name
                if update_data.new_postal_info.org:
                    etree.SubElement(postal, "{%s}org" % CONTACT_NS).text = update_data.new_postal_info.org
                addr = etree.SubElement(postal, "{%s}addr" % CONTACT_NS)
                for street in update_data.new_postal_info.street:
                    etree.SubElement(addr, "{%s}street" % CONTACT_NS).text = street
                etree.SubElement(addr, "{%s}city" % CONTACT_NS).text = update_data.new_postal_info.city
                if update_data.new_postal_info.sp:
                    etree.SubElement(addr, "{%s}sp" % CONTACT_NS).text = update_data.new_postal_info.sp
                if update_data.new_postal_info.pc:
                    etree.SubElement(addr, "{%s}pc" % CONTACT_NS).text = update_data.new_postal_info.pc
                etree.SubElement(addr, "{%s}cc" % CONTACT_NS).text = update_data.new_postal_info.cc

            if update_data.new_voice:
                etree.SubElement(chg, "{%s}voice" % CONTACT_NS).text = update_data.new_voice
            if update_data.new_fax:
                etree.SubElement(chg, "{%s}fax" % CONTACT_NS).text = update_data.new_fax
            if update_data.new_email:
                etree.SubElement(chg, "{%s}email" % CONTACT_NS).text = update_data.new_email
            if update_data.new_auth_info:
                auth = etree.SubElement(chg, "{%s}authInfo" % CONTACT_NS)
                etree.SubElement(auth, "{%s}pw" % CONTACT_NS).text = update_data.new_auth_info

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    # =========================================================================
    # Host Commands
    # =========================================================================

    @staticmethod
    def build_host_check(names: List[str], cl_trid: str = None) -> bytes:
        """Build host:check command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        check = etree.SubElement(command, "{%s}check" % EPP_NS)

        host_check = etree.SubElement(check, "{%s}check" % HOST_NS)
        for name in names:
            etree.SubElement(host_check, "{%s}name" % HOST_NS).text = name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_host_info(name: str, cl_trid: str = None) -> bytes:
        """Build host:info command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        info = etree.SubElement(command, "{%s}info" % EPP_NS)

        host_info = etree.SubElement(info, "{%s}info" % HOST_NS)
        etree.SubElement(host_info, "{%s}name" % HOST_NS).text = name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_host_create(create_data: HostCreate, cl_trid: str = None) -> bytes:
        """Build host:create command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        create = etree.SubElement(command, "{%s}create" % EPP_NS)

        host_create = etree.SubElement(create, "{%s}create" % HOST_NS)
        etree.SubElement(host_create, "{%s}name" % HOST_NS).text = create_data.name

        for addr in create_data.addresses:
            a = etree.SubElement(host_create, "{%s}addr" % HOST_NS)
            a.text = addr.address
            a.set("ip", addr.ip_version)

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_host_delete(name: str, cl_trid: str = None) -> bytes:
        """Build host:delete command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        delete = etree.SubElement(command, "{%s}delete" % EPP_NS)

        host_delete = etree.SubElement(delete, "{%s}delete" % HOST_NS)
        etree.SubElement(host_delete, "{%s}name" % HOST_NS).text = name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)

    @staticmethod
    def build_host_update(update_data: HostUpdate, cl_trid: str = None) -> bytes:
        """Build host:update command."""
        root = _create_epp_root()
        command = etree.SubElement(root, "{%s}command" % EPP_NS)
        update_cmd = etree.SubElement(command, "{%s}update" % EPP_NS)

        host_update = etree.SubElement(update_cmd, "{%s}update" % HOST_NS)
        etree.SubElement(host_update, "{%s}name" % HOST_NS).text = update_data.name

        # Add section
        if update_data.add_addresses or update_data.add_status:
            add = etree.SubElement(host_update, "{%s}add" % HOST_NS)
            for addr in update_data.add_addresses:
                a = etree.SubElement(add, "{%s}addr" % HOST_NS)
                a.text = addr.address
                a.set("ip", addr.ip_version)
            for status in update_data.add_status:
                s = etree.SubElement(add, "{%s}status" % HOST_NS)
                s.set("s", status)

        # Remove section
        if update_data.rem_addresses or update_data.rem_status:
            rem = etree.SubElement(host_update, "{%s}rem" % HOST_NS)
            for addr in update_data.rem_addresses:
                a = etree.SubElement(rem, "{%s}addr" % HOST_NS)
                a.text = addr.address
                a.set("ip", addr.ip_version)
            for status in update_data.rem_status:
                s = etree.SubElement(rem, "{%s}status" % HOST_NS)
                s.set("s", status)

        # Change section
        if update_data.new_name:
            chg = etree.SubElement(host_update, "{%s}chg" % HOST_NS)
            etree.SubElement(chg, "{%s}name" % HOST_NS).text = update_data.new_name

        _add_cl_trid(command, cl_trid)
        return _to_bytes(root)
