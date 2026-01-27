"""
EPP XML Processor

Parses incoming EPP XML commands and extracts command type and parameters.
Uses lxml for high-performance XML processing with namespace support.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from lxml import etree

logger = logging.getLogger("epp.xml")

# EPP Namespaces
EPP_NS = "urn:ietf:params:xml:ns:epp-1.0"
DOMAIN_NS = "urn:ietf:params:xml:ns:domain-1.0"
CONTACT_NS = "urn:ietf:params:xml:ns:contact-1.0"
HOST_NS = "urn:ietf:params:xml:ns:host-1.0"

# Extension Namespaces
AEEXT_NS = "urn:X-ae:params:xml:ns:aeext-1.0"
AREXT_NS = "urn:X-ar:params:xml:ns:arext-1.0"
AUEXT_NS = "urn:X-au:params:xml:ns:auext-1.1"
E164_NS = "urn:ietf:params:xml:ns:e164epp-1.0"
SECDNS_NS = "urn:ietf:params:xml:ns:secDNS-1.1"
IDN_NS = "urn:X-ar:params:xml:ns:idnadomain-1.0"
VARIANT_NS = "urn:X-ar:params:xml:ns:variant-1.0"
SYNC_NS = "urn:X-ar:params:xml:ns:sync-1.0"
KV_NS = "urn:X-ar:params:xml:ns:kv-1.0"

# Namespace map for XPath queries
NSMAP = {
    "epp": EPP_NS,
    "domain": DOMAIN_NS,
    "contact": CONTACT_NS,
    "host": HOST_NS,
    "aeext": AEEXT_NS,
    "arext": AREXT_NS,
    "e164": E164_NS,
    "secDNS": SECDNS_NS,
    "idnadomain": IDN_NS,
    "variant": VARIANT_NS,
    "sync": SYNC_NS,
    "kv": KV_NS,
}


class XMLParseError(Exception):
    """Error parsing XML"""
    pass


class XMLValidationError(Exception):
    """XML validation error"""
    pass


@dataclass
class EPPCommand:
    """Parsed EPP command"""
    command_type: str  # hello, login, logout, check, info, create, etc.
    object_type: Optional[str] = None  # domain, contact, host, or None for session commands
    client_transaction_id: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    extensions: Dict[str, Any] = field(default_factory=dict)
    raw_xml: Optional[bytes] = None


def _find_element(parent: etree._Element, name: str, nsmap: dict = None) -> Optional[etree._Element]:
    """
    Find element with namespace fallback.

    Uses explicit 'is not None' check to avoid lxml element truth-testing issues.
    """
    if nsmap:
        elem = parent.find(f"epp:{name}", nsmap)
        if elem is not None:
            return elem
    elem = parent.find(name)
    if elem is not None:
        return elem
    return None


class XMLProcessor:
    """
    Processes EPP XML messages.

    Handles parsing of incoming commands and extraction of:
    - Command type (login, check, info, create, etc.)
    - Object type (domain, contact, host)
    - Command parameters
    - Client transaction ID
    - Extensions
    """

    def __init__(self):
        """Initialize XML processor with parser configuration."""
        # Configure parser to be secure against XML attacks
        self._parser = etree.XMLParser(
            remove_blank_text=True,
            remove_comments=True,
            resolve_entities=False,
            no_network=True,
            huge_tree=False
        )

    def parse(self, xml_data: bytes) -> EPPCommand:
        """
        Parse EPP XML and extract command information.

        Args:
            xml_data: Raw XML bytes

        Returns:
            EPPCommand with parsed data

        Raises:
            XMLParseError: If XML is malformed
            XMLValidationError: If XML structure is invalid
        """
        try:
            root = etree.fromstring(xml_data, parser=self._parser)
        except etree.XMLSyntaxError as e:
            logger.error(f"XML syntax error: {e}")
            raise XMLParseError(f"Invalid XML: {e}") from e

        # Verify root element is <epp>
        if not root.tag.endswith("}epp") and root.tag != "epp":
            raise XMLValidationError(f"Root element must be 'epp', got '{root.tag}'")

        # Check for hello (no child elements needed)
        hello = _find_element(root, "hello", NSMAP)
        if hello is not None:
            return EPPCommand(
                command_type="hello",
                raw_xml=xml_data
            )

        # Find command element
        command_elem = _find_element(root, "command", NSMAP)
        if command_elem is None:
            raise XMLValidationError("Missing <command> element")

        # Extract client transaction ID
        cl_trid_elem = _find_element(command_elem, "clTRID", NSMAP)
        cl_trid = cl_trid_elem.text if cl_trid_elem is not None else None

        # Determine command type
        command_type, object_type, data = self._parse_command(command_elem)

        # Extract extensions
        extensions = self._parse_extensions(command_elem)

        return EPPCommand(
            command_type=command_type,
            object_type=object_type,
            client_transaction_id=cl_trid,
            data=data,
            extensions=extensions,
            raw_xml=xml_data
        )

    def _parse_command(
        self,
        command_elem: etree._Element
    ) -> Tuple[str, Optional[str], Dict[str, Any]]:
        """
        Parse the command element to determine type and extract data.

        Returns:
            Tuple of (command_type, object_type, data)
        """
        # Session commands (no object type)
        for cmd in ["login", "logout"]:
            elem = _find_element(command_elem, cmd, NSMAP)
            if elem is not None:
                data = self._parse_login(elem) if cmd == "login" else {}
                return cmd, None, data

        # Poll command
        poll_elem = _find_element(command_elem, "poll", NSMAP)
        if poll_elem is not None:
            op = poll_elem.get("op", "req")
            msg_id = poll_elem.get("msgID")
            return "poll", None, {"op": op, "msgID": msg_id}

        # Check for AE extension protocol command (aeext:command)
        ae_cmd = command_elem.find(f"{{{AEEXT_NS}}}command")
        if ae_cmd is not None:
            return self._parse_aeext_command(ae_cmd)

        # Check for AR extension protocol command (arext:command)
        ar_cmd = command_elem.find(f"{{{AREXT_NS}}}command")
        if ar_cmd is not None:
            return self._parse_arext_command(ar_cmd)

        # Check for AU extension protocol command (auext:command)
        au_cmd = command_elem.find(f"{{{AUEXT_NS}}}command")
        if au_cmd is not None:
            return self._parse_auext_command(au_cmd)

        # Object commands
        for cmd in ["check", "info", "create", "delete", "update", "renew", "transfer"]:
            elem = _find_element(command_elem, cmd, NSMAP)
            if elem is not None:
                object_type, data = self._parse_object_command(cmd, elem)
                return cmd, object_type, data

        raise XMLValidationError("Unknown or missing command type")

    def _parse_login(self, login_elem: etree._Element) -> Dict[str, Any]:
        """Parse login command data."""
        data = {}

        # Client ID
        clid = _find_element(login_elem, "clID", NSMAP)
        if clid is not None:
            data["clID"] = clid.text

        # Password
        pw = _find_element(login_elem, "pw", NSMAP)
        if pw is not None:
            data["pw"] = pw.text

        # New password (optional)
        newpw = _find_element(login_elem, "newPW", NSMAP)
        if newpw is not None:
            data["newPW"] = newpw.text

        # Options
        options = _find_element(login_elem, "options", NSMAP)
        if options is not None:
            version = _find_element(options, "version", NSMAP)
            lang = _find_element(options, "lang", NSMAP)
            data["version"] = version.text if version is not None else "1.0"
            data["lang"] = lang.text if lang is not None else "en"

        # Services
        svcs = _find_element(login_elem, "svcs", NSMAP)
        if svcs is not None:
            data["objURIs"] = []
            obj_uris = svcs.findall("epp:objURI", NSMAP)
            if not obj_uris:
                obj_uris = svcs.findall("objURI")
            for obj_uri in obj_uris:
                if obj_uri.text:
                    data["objURIs"].append(obj_uri.text)

            # Extension URIs
            svc_ext = _find_element(svcs, "svcExtension", NSMAP)
            if svc_ext is not None:
                data["extURIs"] = []
                ext_uris = svc_ext.findall("epp:extURI", NSMAP)
                if not ext_uris:
                    ext_uris = svc_ext.findall("extURI")
                for ext_uri in ext_uris:
                    if ext_uri.text:
                        data["extURIs"].append(ext_uri.text)

        return data

    def _parse_object_command(
        self,
        cmd: str,
        cmd_elem: etree._Element
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Parse an object command (domain, contact, host).

        Returns:
            Tuple of (object_type, data)
        """
        # For transfer commands, capture the op attribute from the outer element
        transfer_op = None
        if cmd == "transfer":
            transfer_op = cmd_elem.get("op", "request")

        # Find the object-specific element
        for obj_type, ns in [("domain", DOMAIN_NS), ("contact", CONTACT_NS), ("host", HOST_NS)]:
            obj_elem = cmd_elem.find(f"{{{ns}}}{cmd}")
            if obj_elem is not None:
                parser = getattr(self, f"_parse_{obj_type}_{cmd}", None)
                if parser:
                    data = parser(obj_elem)
                else:
                    data = self._generic_parse(obj_elem)

                # Add transfer op if this is a transfer command
                if transfer_op is not None:
                    data["op"] = transfer_op

                return obj_type, data

        raise XMLValidationError(f"No object found in {cmd} command")

    def _parse_domain_check(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse domain:check command."""
        names = []
        for name in elem.findall(f"{{{DOMAIN_NS}}}name"):
            if name.text:
                names.append(name.text.lower())
        return {"names": names}

    def _parse_domain_info(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse domain:info command."""
        data = {}
        name = elem.find(f"{{{DOMAIN_NS}}}name")
        if name is not None:
            data["name"] = name.text.lower() if name.text else None
            data["hosts"] = name.get("hosts", "all")

        auth_info = elem.find(f"{{{DOMAIN_NS}}}authInfo")
        if auth_info is not None:
            pw = auth_info.find(f"{{{DOMAIN_NS}}}pw")
            if pw is not None:
                data["authInfo"] = pw.text

        return data

    def _parse_domain_create(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse domain:create command."""
        data = {}

        # Domain name
        name = elem.find(f"{{{DOMAIN_NS}}}name")
        if name is not None:
            data["name"] = name.text.lower() if name.text else None

        # Period
        period = elem.find(f"{{{DOMAIN_NS}}}period")
        if period is not None:
            data["period"] = int(period.text) if period.text else 1
            data["period_unit"] = period.get("unit", "y")

        # Nameservers
        ns_elem = elem.find(f"{{{DOMAIN_NS}}}ns")
        if ns_elem is not None:
            data["nameservers"] = []
            for host_obj in ns_elem.findall(f"{{{DOMAIN_NS}}}hostObj"):
                if host_obj.text:
                    data["nameservers"].append(host_obj.text.lower())
            for host_attr in ns_elem.findall(f"{{{DOMAIN_NS}}}hostAttr"):
                host_name = host_attr.find(f"{{{DOMAIN_NS}}}hostName")
                if host_name is not None and host_name.text:
                    ns_data = {"name": host_name.text.lower(), "addrs": []}
                    for addr in host_attr.findall(f"{{{DOMAIN_NS}}}hostAddr"):
                        if addr.text:
                            ns_data["addrs"].append({
                                "addr": addr.text,
                                "ip": addr.get("ip", "v4")
                            })
                    data["nameservers"].append(ns_data)

        # Registrant
        registrant = elem.find(f"{{{DOMAIN_NS}}}registrant")
        if registrant is not None:
            data["registrant"] = registrant.text

        # Contacts
        data["contacts"] = []
        for contact in elem.findall(f"{{{DOMAIN_NS}}}contact"):
            if contact.text:
                data["contacts"].append({
                    "id": contact.text,
                    "type": contact.get("type")
                })

        # Auth info
        auth_info = elem.find(f"{{{DOMAIN_NS}}}authInfo")
        if auth_info is not None:
            pw = auth_info.find(f"{{{DOMAIN_NS}}}pw")
            if pw is not None:
                data["authInfo"] = pw.text

        return data

    def _parse_domain_update(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse domain:update command."""
        data = {}

        # Domain name
        name = elem.find(f"{{{DOMAIN_NS}}}name")
        if name is not None:
            data["name"] = name.text.lower() if name.text else None

        # Add section
        add = elem.find(f"{{{DOMAIN_NS}}}add")
        if add is not None:
            data["add"] = self._parse_domain_update_section(add)

        # Remove section
        rem = elem.find(f"{{{DOMAIN_NS}}}rem")
        if rem is not None:
            data["rem"] = self._parse_domain_update_section(rem)

        # Change section
        chg = elem.find(f"{{{DOMAIN_NS}}}chg")
        if chg is not None:
            data["chg"] = {}
            registrant = chg.find(f"{{{DOMAIN_NS}}}registrant")
            if registrant is not None:
                data["chg"]["registrant"] = registrant.text
            auth_info = chg.find(f"{{{DOMAIN_NS}}}authInfo")
            if auth_info is not None:
                pw = auth_info.find(f"{{{DOMAIN_NS}}}pw")
                if pw is not None:
                    data["chg"]["authInfo"] = pw.text

        return data

    def _parse_domain_update_section(self, section: etree._Element) -> Dict[str, Any]:
        """Parse add/rem section of domain:update."""
        data = {}

        # Nameservers
        ns_elem = section.find(f"{{{DOMAIN_NS}}}ns")
        if ns_elem is not None:
            data["nameservers"] = []
            for host_obj in ns_elem.findall(f"{{{DOMAIN_NS}}}hostObj"):
                if host_obj.text:
                    data["nameservers"].append(host_obj.text.lower())

        # Contacts
        contacts = []
        for contact in section.findall(f"{{{DOMAIN_NS}}}contact"):
            if contact.text:
                contacts.append({
                    "id": contact.text,
                    "type": contact.get("type")
                })
        if contacts:
            data["contacts"] = contacts

        # Statuses
        statuses = []
        for status in section.findall(f"{{{DOMAIN_NS}}}status"):
            statuses.append({
                "s": status.get("s"),
                "lang": status.get("lang"),
                "reason": status.text
            })
        if statuses:
            data["statuses"] = statuses

        return data

    def _parse_domain_delete(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse domain:delete command."""
        data = {}
        name = elem.find(f"{{{DOMAIN_NS}}}name")
        if name is not None:
            data["name"] = name.text.lower() if name.text else None
        return data

    def _parse_domain_renew(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse domain:renew command."""
        data = {}

        name = elem.find(f"{{{DOMAIN_NS}}}name")
        if name is not None:
            data["name"] = name.text.lower() if name.text else None

        cur_exp = elem.find(f"{{{DOMAIN_NS}}}curExpDate")
        if cur_exp is not None:
            data["curExpDate"] = cur_exp.text

        period = elem.find(f"{{{DOMAIN_NS}}}period")
        if period is not None:
            data["period"] = int(period.text) if period.text else 1
            data["period_unit"] = period.get("unit", "y")

        return data

    def _parse_domain_transfer(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse domain:transfer command."""
        data = {}

        name = elem.find(f"{{{DOMAIN_NS}}}name")
        if name is not None:
            data["name"] = name.text.lower() if name.text else None

        period = elem.find(f"{{{DOMAIN_NS}}}period")
        if period is not None:
            data["period"] = int(period.text) if period.text else None
            data["period_unit"] = period.get("unit", "y")

        auth_info = elem.find(f"{{{DOMAIN_NS}}}authInfo")
        if auth_info is not None:
            pw = auth_info.find(f"{{{DOMAIN_NS}}}pw")
            if pw is not None:
                data["authInfo"] = pw.text
                data["authInfo_roid"] = pw.get("roid")

        return data

    def _parse_contact_check(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse contact:check command."""
        ids = []
        for id_elem in elem.findall(f"{{{CONTACT_NS}}}id"):
            if id_elem.text:
                ids.append(id_elem.text)
        return {"ids": ids}

    def _parse_contact_info(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse contact:info command."""
        data = {}
        id_elem = elem.find(f"{{{CONTACT_NS}}}id")
        if id_elem is not None:
            data["id"] = id_elem.text

        auth_info = elem.find(f"{{{CONTACT_NS}}}authInfo")
        if auth_info is not None:
            pw = auth_info.find(f"{{{CONTACT_NS}}}pw")
            if pw is not None:
                data["authInfo"] = pw.text

        return data

    def _parse_contact_create(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse contact:create command."""
        data = {}

        id_elem = elem.find(f"{{{CONTACT_NS}}}id")
        if id_elem is not None:
            data["id"] = id_elem.text

        # Postal info (can have int and/or loc types)
        for postal in elem.findall(f"{{{CONTACT_NS}}}postalInfo"):
            postal_type = postal.get("type", "int")
            postal_data = self._parse_postal_info(postal)
            data[f"postalInfo_{postal_type}"] = postal_data

        # Voice
        voice = elem.find(f"{{{CONTACT_NS}}}voice")
        if voice is not None:
            data["voice"] = voice.text
            data["voice_ext"] = voice.get("x")

        # Fax
        fax = elem.find(f"{{{CONTACT_NS}}}fax")
        if fax is not None:
            data["fax"] = fax.text
            data["fax_ext"] = fax.get("x")

        # Email
        email = elem.find(f"{{{CONTACT_NS}}}email")
        if email is not None:
            data["email"] = email.text

        # Auth info
        auth_info = elem.find(f"{{{CONTACT_NS}}}authInfo")
        if auth_info is not None:
            pw = auth_info.find(f"{{{CONTACT_NS}}}pw")
            if pw is not None:
                data["authInfo"] = pw.text

        # Disclose
        disclose = elem.find(f"{{{CONTACT_NS}}}disclose")
        if disclose is not None:
            data["disclose"] = {
                "flag": disclose.get("flag", "1"),
                "elements": [child.tag.split("}")[-1] for child in disclose]
            }

        return data

    def _parse_postal_info(self, postal: etree._Element) -> Dict[str, Any]:
        """Parse contact postal info."""
        data = {}

        name = postal.find(f"{{{CONTACT_NS}}}name")
        if name is not None:
            data["name"] = name.text

        org = postal.find(f"{{{CONTACT_NS}}}org")
        if org is not None:
            data["org"] = org.text

        addr = postal.find(f"{{{CONTACT_NS}}}addr")
        if addr is not None:
            streets = []
            for street in addr.findall(f"{{{CONTACT_NS}}}street"):
                if street.text:
                    streets.append(street.text)
            data["street"] = streets

            city = addr.find(f"{{{CONTACT_NS}}}city")
            if city is not None:
                data["city"] = city.text

            sp = addr.find(f"{{{CONTACT_NS}}}sp")
            if sp is not None:
                data["sp"] = sp.text

            pc = addr.find(f"{{{CONTACT_NS}}}pc")
            if pc is not None:
                data["pc"] = pc.text

            cc = addr.find(f"{{{CONTACT_NS}}}cc")
            if cc is not None:
                data["cc"] = cc.text

        return data

    def _parse_contact_update(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse contact:update command."""
        data = {}

        id_elem = elem.find(f"{{{CONTACT_NS}}}id")
        if id_elem is not None:
            data["id"] = id_elem.text

        # Add statuses
        add = elem.find(f"{{{CONTACT_NS}}}add")
        if add is not None:
            statuses = []
            for status in add.findall(f"{{{CONTACT_NS}}}status"):
                statuses.append({
                    "s": status.get("s"),
                    "lang": status.get("lang"),
                    "reason": status.text
                })
            if statuses:
                data["add_statuses"] = statuses

        # Remove statuses
        rem = elem.find(f"{{{CONTACT_NS}}}rem")
        if rem is not None:
            statuses = []
            for status in rem.findall(f"{{{CONTACT_NS}}}status"):
                statuses.append({"s": status.get("s")})
            if statuses:
                data["rem_statuses"] = statuses

        # Change section
        chg = elem.find(f"{{{CONTACT_NS}}}chg")
        if chg is not None:
            data["chg"] = self._parse_contact_create(chg)

        return data

    def _parse_contact_delete(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse contact:delete command."""
        data = {}
        id_elem = elem.find(f"{{{CONTACT_NS}}}id")
        if id_elem is not None:
            data["id"] = id_elem.text
        return data

    def _parse_contact_transfer(self, elem: etree._Element) -> Dict[str, Any]:
        """
        Parse contact:transfer command.

        Per RFC 5733, contact transfer uses authIDType:
        - id: Contact identifier (required)
        - authInfo: Authorization info (required for request, optional for query)
        """
        data = {}

        # Contact ID (required)
        id_elem = elem.find(f"{{{CONTACT_NS}}}id")
        if id_elem is not None:
            data["id"] = id_elem.text

        # Auth info (required for request op, optional otherwise)
        auth_info = elem.find(f"{{{CONTACT_NS}}}authInfo")
        if auth_info is not None:
            pw = auth_info.find(f"{{{CONTACT_NS}}}pw")
            if pw is not None:
                data["authInfo"] = pw.text
                # ROID attribute for linked auth info
                roid = pw.get("roid")
                if roid:
                    data["authInfo_roid"] = roid

        return data

    def _parse_host_check(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse host:check command."""
        names = []
        for name in elem.findall(f"{{{HOST_NS}}}name"):
            if name.text:
                names.append(name.text.lower())
        return {"names": names}

    def _parse_host_info(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse host:info command."""
        data = {}
        name = elem.find(f"{{{HOST_NS}}}name")
        if name is not None:
            data["name"] = name.text.lower() if name.text else None
        return data

    def _parse_host_create(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse host:create command."""
        data = {}

        name = elem.find(f"{{{HOST_NS}}}name")
        if name is not None:
            data["name"] = name.text.lower() if name.text else None

        addrs = []
        for addr in elem.findall(f"{{{HOST_NS}}}addr"):
            if addr.text:
                addrs.append({
                    "addr": addr.text,
                    "ip": addr.get("ip", "v4")
                })
        data["addrs"] = addrs

        return data

    def _parse_host_update(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse host:update command."""
        data = {}

        name = elem.find(f"{{{HOST_NS}}}name")
        if name is not None:
            data["name"] = name.text.lower() if name.text else None

        # Add section
        add = elem.find(f"{{{HOST_NS}}}add")
        if add is not None:
            data["add"] = {"addrs": [], "statuses": []}
            for addr in add.findall(f"{{{HOST_NS}}}addr"):
                if addr.text:
                    data["add"]["addrs"].append({
                        "addr": addr.text,
                        "ip": addr.get("ip", "v4")
                    })
            for status in add.findall(f"{{{HOST_NS}}}status"):
                data["add"]["statuses"].append({
                    "s": status.get("s"),
                    "lang": status.get("lang"),
                    "reason": status.text
                })

        # Remove section
        rem = elem.find(f"{{{HOST_NS}}}rem")
        if rem is not None:
            data["rem"] = {"addrs": [], "statuses": []}
            for addr in rem.findall(f"{{{HOST_NS}}}addr"):
                if addr.text:
                    data["rem"]["addrs"].append({
                        "addr": addr.text,
                        "ip": addr.get("ip", "v4")
                    })
            for status in rem.findall(f"{{{HOST_NS}}}status"):
                data["rem"]["statuses"].append({"s": status.get("s")})

        # Change section (name change)
        chg = elem.find(f"{{{HOST_NS}}}chg")
        if chg is not None:
            new_name = chg.find(f"{{{HOST_NS}}}name")
            if new_name is not None:
                data["chg"] = {"name": new_name.text.lower() if new_name.text else None}

        return data

    def _parse_host_delete(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse host:delete command."""
        data = {}
        name = elem.find(f"{{{HOST_NS}}}name")
        if name is not None:
            data["name"] = name.text.lower() if name.text else None
        return data

    def _parse_aeext_command(
        self,
        cmd_elem: etree._Element
    ) -> Tuple[str, Optional[str], Dict[str, Any]]:
        """
        Parse aeext:command protocol extension.

        Handles:
        - registrantTransfer: Transfer domain to new legal entity

        Returns:
            Tuple of (command_type, object_type, data)
        """
        # Check for registrantTransfer
        reg_transfer = cmd_elem.find(f"{{{AEEXT_NS}}}registrantTransfer")
        if reg_transfer is not None:
            data = self._parse_ae_registrant_transfer(reg_transfer)
            return "ae_transfer_registrant", "domain", data

        raise XMLValidationError("Unknown aeext:command type")

    def _parse_ae_registrant_transfer(
        self,
        elem: etree._Element
    ) -> Dict[str, Any]:
        """
        Parse aeext:registrantTransfer command.

        Per aeext-1.0.xsd, registrantTransfer contains:
        - name: Domain name (required)
        - curExpDate: Current expiry date (required, prevents replay)
        - aeProperties: Required AE properties
        - period: Optional validity period
        - explanation: Required explanation (max 1000 chars)
        """
        data = {}

        # Domain name
        name = elem.find(f"{{{AEEXT_NS}}}name")
        if name is not None and name.text:
            data["name"] = name.text.lower()

        # Current expiry date (required to prevent replay)
        cur_exp = elem.find(f"{{{AEEXT_NS}}}curExpDate")
        if cur_exp is not None and cur_exp.text:
            data["curExpDate"] = cur_exp.text

        # Period (optional, defaults to 1 year)
        period = elem.find(f"{{{AEEXT_NS}}}period")
        if period is not None:
            data["period"] = int(period.text) if period.text else 1
            data["period_unit"] = period.get("unit", "y")

        # AE properties
        ae_props = elem.find(f"{{{AEEXT_NS}}}aeProperties")
        if ae_props is not None:
            props = self._parse_ae_properties(ae_props)
            data.update(props)

        # Explanation (required)
        explanation = elem.find(f"{{{AEEXT_NS}}}explanation")
        if explanation is not None and explanation.text:
            data["explanation"] = explanation.text

        return data

    def _parse_ae_properties(self, elem: etree._Element) -> Dict[str, Any]:
        """
        Parse aeext:aeProperties element.

        Per aeext-1.0.xsd:
        - registrantName: Required
        - registrantID + type: Optional
        - eligibilityType: Required
        - eligibilityName: Optional
        - eligibilityID + type: Optional
        - policyReason: Optional (1-99)
        """
        data = {}

        # registrantName (required)
        registrant_name = elem.find(f"{{{AEEXT_NS}}}registrantName")
        if registrant_name is not None and registrant_name.text:
            data["registrantName"] = registrant_name.text

        # registrantID (optional, has type attribute)
        registrant_id = elem.find(f"{{{AEEXT_NS}}}registrantID")
        if registrant_id is not None and registrant_id.text:
            data["registrantID"] = registrant_id.text
            data["registrantIDType"] = registrant_id.get("type")

        # eligibilityType (required)
        elig_type = elem.find(f"{{{AEEXT_NS}}}eligibilityType")
        if elig_type is not None and elig_type.text:
            data["eligibilityType"] = elig_type.text

        # eligibilityName (optional)
        elig_name = elem.find(f"{{{AEEXT_NS}}}eligibilityName")
        if elig_name is not None and elig_name.text:
            data["eligibilityName"] = elig_name.text

        # eligibilityID (optional, has type attribute)
        elig_id = elem.find(f"{{{AEEXT_NS}}}eligibilityID")
        if elig_id is not None and elig_id.text:
            data["eligibilityID"] = elig_id.text
            data["eligibilityIDType"] = elig_id.get("type")

        # policyReason (optional, integer 1-99)
        policy_reason = elem.find(f"{{{AEEXT_NS}}}policyReason")
        if policy_reason is not None and policy_reason.text:
            data["policyReason"] = int(policy_reason.text)

        return data

    def _parse_arext_command(
        self,
        cmd_elem: etree._Element
    ) -> Tuple[str, Optional[str], Dict[str, Any]]:
        """
        Parse arext:command protocol extension.

        Handles:
        - undelete: Restore a deleted domain
        - unrenew: Cancel a pending renewal
        - policyDelete: Delete for policy violation

        Returns:
            Tuple of (command_type, object_type, data)
        """
        # Check for undelete
        undelete = cmd_elem.find(f"{{{AREXT_NS}}}undelete")
        if undelete is not None:
            data = self._parse_ar_domain_name_only(undelete)
            return "ar_undelete", "domain", data

        # Check for unrenew
        unrenew = cmd_elem.find(f"{{{AREXT_NS}}}unrenew")
        if unrenew is not None:
            data = self._parse_ar_domain_name_only(unrenew)
            return "ar_unrenew", "domain", data

        # Check for policyDelete
        policy_delete = cmd_elem.find(f"{{{AREXT_NS}}}policyDelete")
        if policy_delete is not None:
            data = self._parse_ar_policy_delete(policy_delete)
            return "ar_policy_delete", "domain", data

        raise XMLValidationError("Unknown arext:command type")

    def _parse_ar_domain_name_only(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse AR command with only domain name."""
        data = {}
        name = elem.find(f"{{{AREXT_NS}}}name")
        if name is not None and name.text:
            data["name"] = name.text.lower()
        return data

    def _parse_ar_policy_delete(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse arext:policyDelete command."""
        data = {}
        name = elem.find(f"{{{AREXT_NS}}}name")
        if name is not None and name.text:
            data["name"] = name.text.lower()

        reason = elem.find(f"{{{AREXT_NS}}}reason")
        if reason is not None and reason.text:
            data["reason"] = reason.text

        return data

    def _parse_auext_command(
        self,
        cmd_elem: etree._Element
    ) -> Tuple[str, Optional[str], Dict[str, Any]]:
        """
        Parse auext:command protocol extension.

        Handles:
        - registrantTransfer: Transfer domain to new legal entity

        Returns:
            Tuple of (command_type, object_type, data)
        """
        # Check for registrantTransfer
        reg_transfer = cmd_elem.find(f"{{{AUEXT_NS}}}registrantTransfer")
        if reg_transfer is not None:
            data = self._parse_au_registrant_transfer(reg_transfer)
            return "au_transfer_registrant", "domain", data

        raise XMLValidationError("Unknown auext:command type")

    def _parse_au_registrant_transfer(
        self,
        elem: etree._Element
    ) -> Dict[str, Any]:
        """
        Parse auext:registrantTransfer command.

        Per auext-1.1.xsd, registrantTransfer contains:
        - name: Domain name (required)
        - curExpDate: Current expiry date (required, prevents replay)
        - auProperties: Required AU properties
        - period: Optional validity period
        - explanation: Required explanation (max 1000 chars)
        """
        data = {}

        # Domain name
        name = elem.find(f"{{{AUEXT_NS}}}name")
        if name is not None and name.text:
            data["name"] = name.text.lower()

        # Current expiry date (required to prevent replay)
        cur_exp = elem.find(f"{{{AUEXT_NS}}}curExpDate")
        if cur_exp is not None and cur_exp.text:
            data["curExpDate"] = cur_exp.text

        # Period (optional, defaults to 1 year)
        period = elem.find(f"{{{AUEXT_NS}}}period")
        if period is not None:
            data["period"] = int(period.text) if period.text else 1
            data["period_unit"] = period.get("unit", "y")

        # AU properties
        au_props = elem.find(f"{{{AUEXT_NS}}}auProperties")
        if au_props is not None:
            props = self._parse_au_properties(au_props)
            data.update(props)

        # Explanation (required)
        explanation = elem.find(f"{{{AUEXT_NS}}}explanation")
        if explanation is not None and explanation.text:
            data["explanation"] = explanation.text

        return data

    def _parse_au_properties(self, elem: etree._Element) -> Dict[str, Any]:
        """
        Parse auext:auProperties element.

        Per auext-1.1.xsd:
        - registrantName: Required
        - registrantID + type: Optional
        - eligibilityType: Required
        - eligibilityName: Optional
        - eligibilityID + type: Optional
        - policyReason: Required (1-106)
        """
        data = {}

        # registrantName (required)
        registrant_name = elem.find(f"{{{AUEXT_NS}}}registrantName")
        if registrant_name is not None and registrant_name.text:
            data["registrantName"] = registrant_name.text

        # registrantID (optional, has type attribute)
        registrant_id = elem.find(f"{{{AUEXT_NS}}}registrantID")
        if registrant_id is not None and registrant_id.text:
            data["registrantID"] = registrant_id.text
            data["registrantIDType"] = registrant_id.get("type")

        # eligibilityType (required)
        elig_type = elem.find(f"{{{AUEXT_NS}}}eligibilityType")
        if elig_type is not None and elig_type.text:
            data["eligibilityType"] = elig_type.text

        # eligibilityName (optional)
        elig_name = elem.find(f"{{{AUEXT_NS}}}eligibilityName")
        if elig_name is not None and elig_name.text:
            data["eligibilityName"] = elig_name.text

        # eligibilityID (optional, has type attribute)
        elig_id = elem.find(f"{{{AUEXT_NS}}}eligibilityID")
        if elig_id is not None and elig_id.text:
            data["eligibilityID"] = elig_id.text
            data["eligibilityIDType"] = elig_id.get("type")

        # policyReason (required, integer 1-106)
        policy_reason = elem.find(f"{{{AUEXT_NS}}}policyReason")
        if policy_reason is not None and policy_reason.text:
            data["policyReason"] = int(policy_reason.text)

        return data

    def _parse_extensions(self, command_elem: etree._Element) -> Dict[str, Any]:
        """Parse command extensions."""
        extensions = {}
        ext_elem = _find_element(command_elem, "extension", NSMAP)
        if ext_elem is not None:
            for child in ext_elem:
                ns = child.tag.split("}")[0].strip("{") if "}" in child.tag else None
                tag = child.tag.split("}")[-1]

                # Parse AE extension (aeext:update, aeext:create)
                if ns == AEEXT_NS:
                    extensions["aeext"] = self._parse_aeext_extension(child, tag)
                # Parse AR extension (arext:update)
                elif ns == AREXT_NS:
                    extensions["arext"] = self._parse_arext_extension(child, tag)
                # Parse AU extension (auext:update, auext:create)
                elif ns == AUEXT_NS:
                    extensions["auext"] = self._parse_auext_extension(child, tag)
                # Parse E.164/ENUM extension (e164:create, e164:update)
                elif ns == E164_NS:
                    extensions["e164"] = self._parse_e164_extension(child, tag)
                # Parse secDNS extension (secDNS:create, secDNS:update)
                elif ns == SECDNS_NS:
                    extensions["secDNS"] = self._parse_secdns_extension(child, tag)
                # Parse IDN extension (idnadomain:create)
                elif ns == IDN_NS:
                    extensions["idnadomain"] = self._parse_idn_extension(child, tag)
                # Parse Variant extension (variant:info, variant:update)
                elif ns == VARIANT_NS:
                    extensions["variant"] = self._parse_variant_extension(child, tag)
                # Parse Sync extension (sync:update)
                elif ns == SYNC_NS:
                    extensions["sync"] = self._parse_sync_extension(child, tag)
                # Parse KV extension (kv:create, kv:update)
                elif ns == KV_NS:
                    extensions["kv"] = self._parse_kv_extension(child, tag)
                # Parse AE eligibility extension (legacy support)
                elif "aeEligibility" in tag or "eligibility" in tag.lower():
                    extensions["aeEligibility"] = self._parse_ae_eligibility(child, ns)
                # Parse AE domain extension (legacy support)
                elif "aeDomain" in tag or "domain" in tag.lower() and "ae" in (ns or "").lower():
                    extensions["aeDomain"] = self._parse_ae_domain(child, ns)
                else:
                    # Generic extension parsing - store raw XML
                    extensions[tag] = {
                        "namespace": ns,
                        "xml": etree.tostring(child, encoding="unicode"),
                        "data": self._parse_extension_generic(child)
                    }
        return extensions

    def _parse_aeext_extension(
        self,
        elem: etree._Element,
        tag: str
    ) -> Dict[str, Any]:
        """
        Parse aeext extension attached to domain commands.

        Handles:
        - aeext:create: AE properties for domain create
        - aeext:update: AE properties + explanation for domain update (modify registrant)
        """
        data = {"command": tag}

        # AE properties (present in both create and update)
        ae_props = elem.find(f"{{{AEEXT_NS}}}aeProperties")
        if ae_props is not None:
            props = self._parse_ae_properties(ae_props)
            data.update(props)

        # Explanation (required for update/modify registrant)
        explanation = elem.find(f"{{{AEEXT_NS}}}explanation")
        if explanation is not None and explanation.text:
            data["explanation"] = explanation.text

        return data

    def _parse_arext_extension(
        self,
        elem: etree._Element,
        tag: str
    ) -> Dict[str, Any]:
        """Parse arext extension attached to domain commands."""
        data = {"command": tag}

        # Parse any child elements
        for child in elem:
            child_tag = child.tag.split("}")[-1]
            if child.text and child.text.strip():
                data[child_tag] = child.text.strip()

        return data

    def _parse_auext_extension(
        self,
        elem: etree._Element,
        tag: str
    ) -> Dict[str, Any]:
        """
        Parse auext extension attached to domain commands.

        Handles:
        - auext:create: AU properties for domain create
        - auext:update: AU properties + explanation for domain update (modify registrant)
        """
        data = {"command": tag}

        # AU properties (present in both create and update)
        au_props = elem.find(f"{{{AUEXT_NS}}}auProperties")
        if au_props is not None:
            props = self._parse_au_properties(au_props)
            data.update(props)

        # Explanation (required for update/modify registrant)
        explanation = elem.find(f"{{{AUEXT_NS}}}explanation")
        if explanation is not None and explanation.text:
            data["explanation"] = explanation.text

        return data

    def _parse_e164_extension(
        self,
        elem: etree._Element,
        tag: str
    ) -> Dict[str, Any]:
        """
        Parse E.164/ENUM extension attached to domain commands.

        Per e164epp-1.0.xsd (RFC 4114):
        - e164:create: Contains NAPTR records for domain create
        - e164:update: Contains add/rem for NAPTR records

        NAPTR record structure:
        - order: unsigned short (required)
        - pref: unsigned short (required)
        - flags: single character [A-Za-z0-9] (optional)
        - svc: service field (required)
        - regex: regular expression (optional)
        - repl: replacement domain (optional)
        """
        data = {"command": tag, "naptr": []}

        if tag == "create":
            # Parse NAPTR records for create
            for naptr in elem.findall(f"{{{E164_NS}}}naptr"):
                record = self._parse_e164_naptr(naptr)
                if record:
                    data["naptr"].append(record)

        elif tag == "update":
            # Parse add section
            add_elem = elem.find(f"{{{E164_NS}}}add")
            if add_elem is not None:
                data["add_naptr"] = []
                for naptr in add_elem.findall(f"{{{E164_NS}}}naptr"):
                    record = self._parse_e164_naptr(naptr)
                    if record:
                        data["add_naptr"].append(record)

            # Parse rem section
            rem_elem = elem.find(f"{{{E164_NS}}}rem")
            if rem_elem is not None:
                data["rem_naptr"] = []
                for naptr in rem_elem.findall(f"{{{E164_NS}}}naptr"):
                    record = self._parse_e164_naptr(naptr)
                    if record:
                        data["rem_naptr"].append(record)

        return data

    def _parse_e164_naptr(self, elem: etree._Element) -> Dict[str, Any]:
        """
        Parse a single e164:naptr element.

        Returns:
            Dict with order, pref, flags, svc, regex, repl fields
        """
        record = {}

        # order (required)
        order = elem.find(f"{{{E164_NS}}}order")
        if order is not None and order.text:
            record["order"] = int(order.text)

        # pref (required)
        pref = elem.find(f"{{{E164_NS}}}pref")
        if pref is not None and pref.text:
            record["pref"] = int(pref.text)

        # flags (optional, single char)
        flags = elem.find(f"{{{E164_NS}}}flags")
        if flags is not None and flags.text:
            record["flags"] = flags.text

        # svc (required)
        svc = elem.find(f"{{{E164_NS}}}svc")
        if svc is not None and svc.text:
            record["svc"] = svc.text

        # regex (optional)
        regex = elem.find(f"{{{E164_NS}}}regex")
        if regex is not None and regex.text:
            record["regex"] = regex.text

        # repl (optional, max 255 chars)
        repl = elem.find(f"{{{E164_NS}}}repl")
        if repl is not None and repl.text:
            record["repl"] = repl.text

        return record

    def _parse_secdns_extension(
        self,
        elem: etree._Element,
        tag: str
    ) -> Dict[str, Any]:
        """
        Parse secDNS extension (DNSSEC) attached to domain commands.

        Per secDNS-1.1.xsd:
        - secDNS:create: Add DS/Key data to domain create
        - secDNS:update: Add/remove/change DNSSEC data

        DS Data structure:
        - keyTag: unsigned short
        - alg: unsigned byte (algorithm number)
        - digestType: unsigned byte
        - digest: hex binary
        - keyData: optional nested key data

        Key Data structure:
        - flags: unsigned short (256=ZSK, 257=KSK)
        - protocol: unsigned byte (always 3)
        - alg: unsigned byte
        - pubKey: base64 binary
        """
        data = {"command": tag}

        if tag == "create":
            # Parse maxSigLife
            max_sig = elem.find(f"{{{SECDNS_NS}}}maxSigLife")
            if max_sig is not None and max_sig.text:
                data["maxSigLife"] = int(max_sig.text)

            # Parse dsData or keyData
            data["dsData"] = []
            data["keyData"] = []

            for ds in elem.findall(f"{{{SECDNS_NS}}}dsData"):
                ds_record = self._parse_secdns_ds_data(ds)
                if ds_record:
                    data["dsData"].append(ds_record)

            for key in elem.findall(f"{{{SECDNS_NS}}}keyData"):
                key_record = self._parse_secdns_key_data(key)
                if key_record:
                    data["keyData"].append(key_record)

        elif tag == "update":
            # Parse urgent attribute
            data["urgent"] = elem.get("urgent", "false").lower() == "true"

            # Parse rem section
            rem = elem.find(f"{{{SECDNS_NS}}}rem")
            if rem is not None:
                all_elem = rem.find(f"{{{SECDNS_NS}}}all")
                if all_elem is not None and all_elem.text:
                    data["rem_all"] = all_elem.text.lower() == "true"
                else:
                    data["rem_dsData"] = []
                    data["rem_keyData"] = []
                    for ds in rem.findall(f"{{{SECDNS_NS}}}dsData"):
                        ds_record = self._parse_secdns_ds_data(ds)
                        if ds_record:
                            data["rem_dsData"].append(ds_record)
                    for key in rem.findall(f"{{{SECDNS_NS}}}keyData"):
                        key_record = self._parse_secdns_key_data(key)
                        if key_record:
                            data["rem_keyData"].append(key_record)

            # Parse add section
            add = elem.find(f"{{{SECDNS_NS}}}add")
            if add is not None:
                max_sig = add.find(f"{{{SECDNS_NS}}}maxSigLife")
                if max_sig is not None and max_sig.text:
                    data["add_maxSigLife"] = int(max_sig.text)

                data["add_dsData"] = []
                data["add_keyData"] = []
                for ds in add.findall(f"{{{SECDNS_NS}}}dsData"):
                    ds_record = self._parse_secdns_ds_data(ds)
                    if ds_record:
                        data["add_dsData"].append(ds_record)
                for key in add.findall(f"{{{SECDNS_NS}}}keyData"):
                    key_record = self._parse_secdns_key_data(key)
                    if key_record:
                        data["add_keyData"].append(key_record)

            # Parse chg section
            chg = elem.find(f"{{{SECDNS_NS}}}chg")
            if chg is not None:
                max_sig = chg.find(f"{{{SECDNS_NS}}}maxSigLife")
                if max_sig is not None and max_sig.text:
                    data["chg_maxSigLife"] = int(max_sig.text)

        return data

    def _parse_secdns_ds_data(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse a single secDNS:dsData element."""
        record = {}

        key_tag = elem.find(f"{{{SECDNS_NS}}}keyTag")
        if key_tag is not None and key_tag.text:
            record["keyTag"] = int(key_tag.text)

        alg = elem.find(f"{{{SECDNS_NS}}}alg")
        if alg is not None and alg.text:
            record["alg"] = int(alg.text)

        digest_type = elem.find(f"{{{SECDNS_NS}}}digestType")
        if digest_type is not None and digest_type.text:
            record["digestType"] = int(digest_type.text)

        digest = elem.find(f"{{{SECDNS_NS}}}digest")
        if digest is not None and digest.text:
            record["digest"] = digest.text

        # Optional nested keyData
        key_data = elem.find(f"{{{SECDNS_NS}}}keyData")
        if key_data is not None:
            record["keyData"] = self._parse_secdns_key_data(key_data)

        return record

    def _parse_secdns_key_data(self, elem: etree._Element) -> Dict[str, Any]:
        """Parse a single secDNS:keyData element."""
        record = {}

        flags = elem.find(f"{{{SECDNS_NS}}}flags")
        if flags is not None and flags.text:
            record["flags"] = int(flags.text)

        protocol = elem.find(f"{{{SECDNS_NS}}}protocol")
        if protocol is not None and protocol.text:
            record["protocol"] = int(protocol.text)

        alg = elem.find(f"{{{SECDNS_NS}}}alg")
        if alg is not None and alg.text:
            record["alg"] = int(alg.text)

        pub_key = elem.find(f"{{{SECDNS_NS}}}pubKey")
        if pub_key is not None and pub_key.text:
            record["pubKey"] = pub_key.text

        return record

    def _parse_idn_extension(
        self,
        elem: etree._Element,
        tag: str
    ) -> Dict[str, Any]:
        """
        Parse IDN (Internationalized Domain Name) extension.

        Per idnadomain-1.0.xsd:
        - idnadomain:create: Contains userForm with language attribute
        """
        data = {"command": tag}

        if tag == "create":
            user_form = elem.find(f"{{{IDN_NS}}}userForm")
            if user_form is not None:
                data["userForm"] = user_form.text
                data["language"] = user_form.get("language")

        return data

    def _parse_variant_extension(
        self,
        elem: etree._Element,
        tag: str
    ) -> Dict[str, Any]:
        """
        Parse Variant extension for IDN domain variants.

        Per variant-1.0.xsd:
        - variant:info: Query variants (attribute variants="all"|"none")
        - variant:update: Add/remove variants
        """
        data = {"command": tag}

        if tag == "info":
            data["variants"] = elem.get("variants", "all")

        elif tag == "update":
            # Parse add section
            add = elem.find(f"{{{VARIANT_NS}}}add")
            if add is not None:
                data["add_variants"] = []
                for var in add.findall(f"{{{VARIANT_NS}}}variant"):
                    variant_data = {
                        "name": var.text,
                        "userForm": var.get("userForm")
                    }
                    data["add_variants"].append(variant_data)

            # Parse rem section
            rem = elem.find(f"{{{VARIANT_NS}}}rem")
            if rem is not None:
                data["rem_variants"] = []
                for var in rem.findall(f"{{{VARIANT_NS}}}variant"):
                    variant_data = {
                        "name": var.text,
                        "userForm": var.get("userForm")
                    }
                    data["rem_variants"].append(variant_data)

        return data

    def _parse_sync_extension(
        self,
        elem: etree._Element,
        tag: str
    ) -> Dict[str, Any]:
        """
        Parse Sync extension for expiry date synchronization.

        Per sync-1.0.xsd:
        - sync:update: Contains exDate to sync to
        """
        data = {"command": tag}

        if tag == "update":
            ex_date = elem.find(f"{{{SYNC_NS}}}exDate")
            if ex_date is not None and ex_date.text:
                data["exDate"] = ex_date.text

        return data

    def _parse_kv_extension(
        self,
        elem: etree._Element,
        tag: str
    ) -> Dict[str, Any]:
        """
        Parse KV (Key-Value) extension.

        Per kv-1.0.xsd:
        - kv:create: Create kvlists with items
        - kv:update: Update/replace kvlists
        """
        data = {"command": tag, "kvlists": []}

        for kvlist in elem.findall(f"{{{KV_NS}}}kvlist"):
            list_data = {
                "name": kvlist.get("name"),
                "items": []
            }
            for item in kvlist.findall(f"{{{KV_NS}}}item"):
                list_data["items"].append({
                    "key": item.get("key"),
                    "value": item.text
                })
            data["kvlists"].append(list_data)

        return data

    def _parse_ae_eligibility(self, elem: etree._Element, ns: str) -> Dict[str, Any]:
        """
        Parse AE eligibility extension.

        Example:
        <aeEligibility:create xmlns:aeEligibility="urn:aeda:params:xml:ns:aeEligibility-1.0">
            <aeEligibility:eligibilityType>TradeLicense</aeEligibility:eligibilityType>
            <aeEligibility:eligibilityName>Example Company LLC</aeEligibility:eligibilityName>
            <aeEligibility:eligibilityID>123456</aeEligibility:eligibilityID>
            <aeEligibility:eligibilityIDType>TradeLicense</aeEligibility:eligibilityIDType>
            <aeEligibility:policyReason>1</aeEligibility:policyReason>
        </aeEligibility:create>
        """
        data = {"namespace": ns, "fields": {}}

        # Standard AE eligibility fields
        eligibility_fields = [
            "eligibilityType",
            "eligibilityName",
            "eligibilityID",
            "eligibilityIDType",
            "policyReason",
            "registrantID",
            "registrantIDType",
            "registrantName"
        ]

        for field in eligibility_fields:
            # Try with namespace prefix
            field_elem = elem.find(f"{{{ns}}}{field}") if ns else None
            # Try without namespace
            if field_elem is None:
                field_elem = elem.find(f".//{field}")
            # Try local name match
            if field_elem is None:
                for child in elem.iter():
                    local_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if local_name == field:
                        field_elem = child
                        break

            if field_elem is not None and field_elem.text:
                data["fields"][field] = field_elem.text.strip()

        return data

    def _parse_ae_domain(self, elem: etree._Element, ns: str) -> Dict[str, Any]:
        """
        Parse AE domain extension.

        Example:
        <aeDomain:create xmlns:aeDomain="urn:aeda:params:xml:ns:aeDomain-1.0">
            <aeDomain:policyReason>1</aeDomain:policyReason>
        </aeDomain:create>
        """
        data = {"namespace": ns, "fields": {}}

        # Standard AE domain fields
        domain_fields = [
            "policyReason",
            "command"
        ]

        for field in domain_fields:
            field_elem = elem.find(f"{{{ns}}}{field}") if ns else None
            if field_elem is None:
                for child in elem.iter():
                    local_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if local_name == field:
                        field_elem = child
                        break

            if field_elem is not None and field_elem.text:
                data["fields"][field] = field_elem.text.strip()

        return data

    def _parse_extension_generic(self, elem: etree._Element) -> Dict[str, str]:
        """Parse extension element generically."""
        data = {}
        for child in elem.iter():
            if child.text and child.text.strip():
                local_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                data[local_name] = child.text.strip()
        return data

    def _generic_parse(self, elem: etree._Element) -> Dict[str, Any]:
        """Generic element parser for unhandled commands."""
        data = {}
        for child in elem:
            tag = child.tag.split("}")[-1]
            if child.text and child.text.strip():
                data[tag] = child.text.strip()
            if child.attrib:
                data[f"{tag}_attrs"] = dict(child.attrib)
        return data


# Global processor instance
_processor: Optional[XMLProcessor] = None


def get_xml_processor() -> XMLProcessor:
    """Get or create global XML processor."""
    global _processor
    if _processor is None:
        _processor = XMLProcessor()
    return _processor


def parse_epp_xml(xml_data: bytes) -> EPPCommand:
    """
    Convenience function to parse EPP XML.

    Args:
        xml_data: Raw XML bytes

    Returns:
        EPPCommand with parsed data
    """
    return get_xml_processor().parse(xml_data)
