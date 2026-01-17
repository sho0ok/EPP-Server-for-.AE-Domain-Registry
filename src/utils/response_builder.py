"""
EPP Response Builder

Builds EPP XML responses using templates.
All responses conform to RFC 5730 EPP protocol.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from lxml import etree

logger = logging.getLogger("epp.response")

# EPP Namespaces
EPP_NS = "urn:ietf:params:xml:ns:epp-1.0"
DOMAIN_NS = "urn:ietf:params:xml:ns:domain-1.0"
CONTACT_NS = "urn:ietf:params:xml:ns:contact-1.0"
HOST_NS = "urn:ietf:params:xml:ns:host-1.0"

# Namespace declarations for XML output
NSMAP = {
    None: EPP_NS,  # Default namespace
    "domain": DOMAIN_NS,
    "contact": CONTACT_NS,
    "host": HOST_NS,
}

# EPP Response Codes
RESPONSE_CODES = {
    1000: "Command completed successfully",
    1001: "Command completed successfully; action pending",
    1300: "Command completed successfully; no messages",
    1301: "Command completed successfully; ack to dequeue",
    1500: "Command completed successfully; ending session",
    2000: "Unknown command",
    2001: "Command syntax error",
    2002: "Command use error",
    2003: "Required parameter missing",
    2004: "Parameter value range error",
    2005: "Parameter value syntax error",
    2100: "Unimplemented protocol version",
    2101: "Unimplemented command",
    2102: "Unimplemented option",
    2103: "Unimplemented extension",
    2104: "Billing failure",
    2105: "Object is not eligible for renewal",
    2106: "Object is not eligible for transfer",
    2200: "Authentication error",
    2201: "Authorization error",
    2202: "Invalid authorization information",
    2300: "Object pending transfer",
    2301: "Object not pending transfer",
    2302: "Object exists",
    2303: "Object does not exist",
    2304: "Object status prohibits operation",
    2305: "Object association prohibits operation",
    2306: "Parameter value policy error",
    2307: "Unimplemented object service",
    2308: "Data management policy violation",
    2400: "Command failed",
    2500: "Command failed; server closing connection",
    2501: "Authentication error; server closing connection",
    2502: "Session limit exceeded; server closing connection",
}


class ResponseBuilder:
    """
    Builds EPP XML response messages.

    Provides methods to construct:
    - Greeting messages
    - Command responses (success and error)
    - Object-specific result data
    """

    def __init__(
        self,
        server_id: str = "EPP Server",
        roid_suffix: str = "AE",
        supported_versions: Optional[List[str]] = None,
        supported_languages: Optional[List[str]] = None,
        supported_objects: Optional[List[str]] = None,
        supported_extensions: Optional[List[str]] = None
    ):
        """
        Initialize response builder.

        Args:
            server_id: Server identifier for greeting
            roid_suffix: Suffix for server transaction IDs
            supported_versions: List of supported EPP versions
            supported_languages: List of supported languages
            supported_objects: List of supported object URIs
            supported_extensions: List of supported extension URIs
        """
        self.server_id = server_id
        self.roid_suffix = roid_suffix
        self.supported_versions = supported_versions or ["1.0"]
        self.supported_languages = supported_languages or ["en"]
        self.supported_objects = supported_objects or [
            DOMAIN_NS, CONTACT_NS, HOST_NS
        ]
        self.supported_extensions = supported_extensions or []
        self._sv_trid_counter = 0

    def generate_sv_trid(self) -> str:
        """Generate unique server transaction ID."""
        self._sv_trid_counter += 1
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return f"SV-{timestamp}-{self._sv_trid_counter:06d}-{self.roid_suffix}"

    def build_greeting(self) -> bytes:
        """
        Build EPP greeting message.

        Returns:
            XML greeting as bytes
        """
        # Create root element
        epp = etree.Element("{%s}epp" % EPP_NS, nsmap={None: EPP_NS})
        greeting = etree.SubElement(epp, "greeting")

        # Server ID
        etree.SubElement(greeting, "svID").text = self.server_id

        # Server date
        etree.SubElement(greeting, "svDate").text = datetime.utcnow().strftime(
            "%Y-%m-%dT%H:%M:%S.0Z"
        )

        # Services
        svc_menu = etree.SubElement(greeting, "svcMenu")

        # Versions
        for version in self.supported_versions:
            etree.SubElement(svc_menu, "version").text = version

        # Languages
        for lang in self.supported_languages:
            etree.SubElement(svc_menu, "lang").text = lang

        # Object URIs
        for obj_uri in self.supported_objects:
            etree.SubElement(svc_menu, "objURI").text = obj_uri

        # Extensions
        if self.supported_extensions:
            svc_ext = etree.SubElement(svc_menu, "svcExtension")
            for ext_uri in self.supported_extensions:
                etree.SubElement(svc_ext, "extURI").text = ext_uri

        # DCP (Data Collection Policy)
        dcp = etree.SubElement(greeting, "dcp")
        access = etree.SubElement(dcp, "access")
        etree.SubElement(access, "all")
        statement = etree.SubElement(dcp, "statement")
        purpose = etree.SubElement(statement, "purpose")
        etree.SubElement(purpose, "admin")
        etree.SubElement(purpose, "prov")
        recipient = etree.SubElement(statement, "recipient")
        etree.SubElement(recipient, "ours")
        retention = etree.SubElement(statement, "retention")
        etree.SubElement(retention, "stated")

        return etree.tostring(
            epp,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=False
        )

    def build_response(
        self,
        code: int,
        message: Optional[str] = None,
        cl_trid: Optional[str] = None,
        sv_trid: Optional[str] = None,
        result_data: Optional[etree._Element] = None,
        msg_queue: Optional[Dict[str, Any]] = None,
        extensions: Optional[etree._Element] = None
    ) -> bytes:
        """
        Build EPP response message.

        Args:
            code: EPP response code
            message: Optional custom message (defaults to standard)
            cl_trid: Client transaction ID
            sv_trid: Server transaction ID (generated if not provided)
            result_data: Optional resData element content
            msg_queue: Optional message queue info {"count": N, "id": "msg_id"}
            extensions: Optional extension element

        Returns:
            XML response as bytes
        """
        if sv_trid is None:
            sv_trid = self.generate_sv_trid()

        if message is None:
            message = RESPONSE_CODES.get(code, "Unknown response")

        # Create root element
        epp = etree.Element("{%s}epp" % EPP_NS, nsmap={None: EPP_NS})
        response = etree.SubElement(epp, "response")

        # Result
        result = etree.SubElement(response, "result", code=str(code))
        etree.SubElement(result, "msg").text = message

        # Message queue (for poll responses)
        if msg_queue:
            msgQ = etree.SubElement(
                response, "msgQ",
                count=str(msg_queue.get("count", 0)),
                id=str(msg_queue.get("id", ""))
            )
            if "qDate" in msg_queue:
                etree.SubElement(msgQ, "qDate").text = msg_queue["qDate"]
            if "msg" in msg_queue:
                etree.SubElement(msgQ, "msg").text = msg_queue["msg"]

        # Result data
        if result_data is not None:
            res_data = etree.SubElement(response, "resData")
            res_data.append(result_data)

        # Extensions
        if extensions is not None:
            ext = etree.SubElement(response, "extension")
            ext.append(extensions)

        # Transaction IDs
        tr_id = etree.SubElement(response, "trID")
        if cl_trid:
            etree.SubElement(tr_id, "clTRID").text = cl_trid
        etree.SubElement(tr_id, "svTRID").text = sv_trid

        return etree.tostring(
            epp,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=False
        )

    def build_error(
        self,
        code: int,
        message: Optional[str] = None,
        cl_trid: Optional[str] = None,
        sv_trid: Optional[str] = None,
        reason: Optional[str] = None,
        value: Optional[str] = None
    ) -> bytes:
        """
        Build EPP error response.

        Args:
            code: EPP error code
            message: Optional custom message
            cl_trid: Client transaction ID
            sv_trid: Server transaction ID
            reason: Extended error reason
            value: Value that caused the error

        Returns:
            XML error response as bytes
        """
        if sv_trid is None:
            sv_trid = self.generate_sv_trid()

        if message is None:
            message = RESPONSE_CODES.get(code, "Command failed")

        # Create root element
        epp = etree.Element("{%s}epp" % EPP_NS, nsmap={None: EPP_NS})
        response = etree.SubElement(epp, "response")

        # Result with error details
        result = etree.SubElement(response, "result", code=str(code))
        etree.SubElement(result, "msg").text = message

        # Extended error info
        if value:
            ext_value = etree.SubElement(result, "extValue")
            val = etree.SubElement(ext_value, "value")
            val.text = value
            if reason:
                etree.SubElement(ext_value, "reason").text = reason
        elif reason:
            etree.SubElement(result, "extValue")
            # Just add reason in msg if no value
            pass

        # Transaction IDs
        tr_id = etree.SubElement(response, "trID")
        if cl_trid:
            etree.SubElement(tr_id, "clTRID").text = cl_trid
        etree.SubElement(tr_id, "svTRID").text = sv_trid

        return etree.tostring(
            epp,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=False
        )

    # Domain response builders

    def build_domain_check_result(
        self,
        results: List[Dict[str, Any]]
    ) -> etree._Element:
        """
        Build domain:check result data.

        Args:
            results: List of {"name": str, "avail": bool, "reason": str}

        Returns:
            domain:chkData element
        """
        chk_data = etree.Element(
            "{%s}chkData" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )

        for item in results:
            cd = etree.SubElement(chk_data, "{%s}cd" % DOMAIN_NS)
            name = etree.SubElement(
                cd, "{%s}name" % DOMAIN_NS,
                avail="1" if item.get("avail", False) else "0"
            )
            name.text = item["name"]
            if not item.get("avail") and item.get("reason"):
                etree.SubElement(cd, "{%s}reason" % DOMAIN_NS).text = item["reason"]

        return chk_data

    def build_domain_info_result(self, domain: Dict[str, Any]) -> etree._Element:
        """
        Build domain:info result data.

        Args:
            domain: Domain data dictionary

        Returns:
            domain:infData element
        """
        inf_data = etree.Element(
            "{%s}infData" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )

        # Name
        etree.SubElement(inf_data, "{%s}name" % DOMAIN_NS).text = domain["name"]

        # ROID
        etree.SubElement(inf_data, "{%s}roid" % DOMAIN_NS).text = domain["roid"]

        # Status(es)
        for status in domain.get("statuses", []):
            stat_elem = etree.SubElement(
                inf_data, "{%s}status" % DOMAIN_NS,
                s=status["s"]
            )
            if status.get("reason"):
                stat_elem.text = status["reason"]

        # Registrant
        if domain.get("registrant"):
            etree.SubElement(
                inf_data, "{%s}registrant" % DOMAIN_NS
            ).text = domain["registrant"]

        # Contacts
        for contact in domain.get("contacts", []):
            etree.SubElement(
                inf_data, "{%s}contact" % DOMAIN_NS,
                type=contact["type"]
            ).text = contact["id"]

        # Nameservers
        if domain.get("nameservers"):
            ns_elem = etree.SubElement(inf_data, "{%s}ns" % DOMAIN_NS)
            for ns in domain["nameservers"]:
                etree.SubElement(
                    ns_elem, "{%s}hostObj" % DOMAIN_NS
                ).text = ns

        # Hosts (subordinate)
        for host in domain.get("hosts", []):
            etree.SubElement(inf_data, "{%s}host" % DOMAIN_NS).text = host

        # Sponsoring client
        etree.SubElement(
            inf_data, "{%s}clID" % DOMAIN_NS
        ).text = domain.get("clID", "")

        # Creator
        if domain.get("crID"):
            etree.SubElement(inf_data, "{%s}crID" % DOMAIN_NS).text = domain["crID"]

        # Create date
        if domain.get("crDate"):
            etree.SubElement(inf_data, "{%s}crDate" % DOMAIN_NS).text = domain["crDate"]

        # Updater
        if domain.get("upID"):
            etree.SubElement(inf_data, "{%s}upID" % DOMAIN_NS).text = domain["upID"]

        # Update date
        if domain.get("upDate"):
            etree.SubElement(inf_data, "{%s}upDate" % DOMAIN_NS).text = domain["upDate"]

        # Expiry date
        if domain.get("exDate"):
            etree.SubElement(inf_data, "{%s}exDate" % DOMAIN_NS).text = domain["exDate"]

        # Transfer date
        if domain.get("trDate"):
            etree.SubElement(inf_data, "{%s}trDate" % DOMAIN_NS).text = domain["trDate"]

        # Auth info (only if authorized)
        if domain.get("authInfo"):
            auth_info = etree.SubElement(inf_data, "{%s}authInfo" % DOMAIN_NS)
            etree.SubElement(auth_info, "{%s}pw" % DOMAIN_NS).text = domain["authInfo"]

        return inf_data

    def build_domain_create_result(
        self,
        name: str,
        cr_date: str,
        ex_date: str
    ) -> etree._Element:
        """Build domain:create result data."""
        cre_data = etree.Element(
            "{%s}creData" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )
        etree.SubElement(cre_data, "{%s}name" % DOMAIN_NS).text = name
        etree.SubElement(cre_data, "{%s}crDate" % DOMAIN_NS).text = cr_date
        etree.SubElement(cre_data, "{%s}exDate" % DOMAIN_NS).text = ex_date
        return cre_data

    def build_domain_renew_result(
        self,
        name: str,
        ex_date: str
    ) -> etree._Element:
        """Build domain:renew result data."""
        ren_data = etree.Element(
            "{%s}renData" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )
        etree.SubElement(ren_data, "{%s}name" % DOMAIN_NS).text = name
        etree.SubElement(ren_data, "{%s}exDate" % DOMAIN_NS).text = ex_date
        return ren_data

    def build_domain_transfer_result(
        self,
        name: str,
        tr_status: str,
        re_id: str,
        re_date: str,
        ac_id: str,
        ac_date: str,
        ex_date: Optional[str] = None
    ) -> etree._Element:
        """Build domain:transfer result data."""
        trn_data = etree.Element(
            "{%s}trnData" % DOMAIN_NS,
            nsmap={"domain": DOMAIN_NS}
        )
        etree.SubElement(trn_data, "{%s}name" % DOMAIN_NS).text = name
        etree.SubElement(trn_data, "{%s}trStatus" % DOMAIN_NS).text = tr_status
        etree.SubElement(trn_data, "{%s}reID" % DOMAIN_NS).text = re_id
        etree.SubElement(trn_data, "{%s}reDate" % DOMAIN_NS).text = re_date
        etree.SubElement(trn_data, "{%s}acID" % DOMAIN_NS).text = ac_id
        etree.SubElement(trn_data, "{%s}acDate" % DOMAIN_NS).text = ac_date
        if ex_date:
            etree.SubElement(trn_data, "{%s}exDate" % DOMAIN_NS).text = ex_date
        return trn_data

    # Contact response builders

    def build_contact_check_result(
        self,
        results: List[Dict[str, Any]]
    ) -> etree._Element:
        """Build contact:check result data."""
        chk_data = etree.Element(
            "{%s}chkData" % CONTACT_NS,
            nsmap={"contact": CONTACT_NS}
        )

        for item in results:
            cd = etree.SubElement(chk_data, "{%s}cd" % CONTACT_NS)
            id_elem = etree.SubElement(
                cd, "{%s}id" % CONTACT_NS,
                avail="1" if item.get("avail", False) else "0"
            )
            id_elem.text = item["id"]
            if not item.get("avail") and item.get("reason"):
                etree.SubElement(cd, "{%s}reason" % CONTACT_NS).text = item["reason"]

        return chk_data

    def build_contact_info_result(self, contact: Dict[str, Any]) -> etree._Element:
        """Build contact:info result data."""
        inf_data = etree.Element(
            "{%s}infData" % CONTACT_NS,
            nsmap={"contact": CONTACT_NS}
        )

        # ID
        etree.SubElement(inf_data, "{%s}id" % CONTACT_NS).text = contact["id"]

        # ROID
        etree.SubElement(inf_data, "{%s}roid" % CONTACT_NS).text = contact["roid"]

        # Status(es)
        for status in contact.get("statuses", []):
            stat_elem = etree.SubElement(
                inf_data, "{%s}status" % CONTACT_NS,
                s=status["s"]
            )
            if status.get("reason"):
                stat_elem.text = status["reason"]

        # Postal info
        for ptype in ["int", "loc"]:
            postal = contact.get(f"postalInfo_{ptype}")
            if postal:
                postal_elem = etree.SubElement(
                    inf_data, "{%s}postalInfo" % CONTACT_NS,
                    type=ptype
                )
                if postal.get("name"):
                    etree.SubElement(
                        postal_elem, "{%s}name" % CONTACT_NS
                    ).text = postal["name"]
                if postal.get("org"):
                    etree.SubElement(
                        postal_elem, "{%s}org" % CONTACT_NS
                    ).text = postal["org"]

                addr = etree.SubElement(postal_elem, "{%s}addr" % CONTACT_NS)
                for street in postal.get("street", []):
                    etree.SubElement(addr, "{%s}street" % CONTACT_NS).text = street
                etree.SubElement(
                    addr, "{%s}city" % CONTACT_NS
                ).text = postal.get("city", "")
                if postal.get("sp"):
                    etree.SubElement(addr, "{%s}sp" % CONTACT_NS).text = postal["sp"]
                if postal.get("pc"):
                    etree.SubElement(addr, "{%s}pc" % CONTACT_NS).text = postal["pc"]
                etree.SubElement(
                    addr, "{%s}cc" % CONTACT_NS
                ).text = postal.get("cc", "")

        # Voice
        if contact.get("voice"):
            voice = etree.SubElement(inf_data, "{%s}voice" % CONTACT_NS)
            voice.text = contact["voice"]
            if contact.get("voice_ext"):
                voice.set("x", contact["voice_ext"])

        # Fax
        if contact.get("fax"):
            fax = etree.SubElement(inf_data, "{%s}fax" % CONTACT_NS)
            fax.text = contact["fax"]
            if contact.get("fax_ext"):
                fax.set("x", contact["fax_ext"])

        # Email
        etree.SubElement(inf_data, "{%s}email" % CONTACT_NS).text = contact.get("email", "")

        # Sponsoring client
        etree.SubElement(inf_data, "{%s}clID" % CONTACT_NS).text = contact.get("clID", "")

        # Creator
        if contact.get("crID"):
            etree.SubElement(inf_data, "{%s}crID" % CONTACT_NS).text = contact["crID"]

        # Create date
        if contact.get("crDate"):
            etree.SubElement(inf_data, "{%s}crDate" % CONTACT_NS).text = contact["crDate"]

        # Updater
        if contact.get("upID"):
            etree.SubElement(inf_data, "{%s}upID" % CONTACT_NS).text = contact["upID"]

        # Update date
        if contact.get("upDate"):
            etree.SubElement(inf_data, "{%s}upDate" % CONTACT_NS).text = contact["upDate"]

        # Auth info (only if authorized)
        if contact.get("authInfo"):
            auth_info = etree.SubElement(inf_data, "{%s}authInfo" % CONTACT_NS)
            etree.SubElement(auth_info, "{%s}pw" % CONTACT_NS).text = contact["authInfo"]

        return inf_data

    def build_contact_create_result(
        self,
        contact_id: str,
        cr_date: str
    ) -> etree._Element:
        """Build contact:create result data."""
        cre_data = etree.Element(
            "{%s}creData" % CONTACT_NS,
            nsmap={"contact": CONTACT_NS}
        )
        etree.SubElement(cre_data, "{%s}id" % CONTACT_NS).text = contact_id
        etree.SubElement(cre_data, "{%s}crDate" % CONTACT_NS).text = cr_date
        return cre_data

    # Host response builders

    def build_host_check_result(
        self,
        results: List[Dict[str, Any]]
    ) -> etree._Element:
        """Build host:check result data."""
        chk_data = etree.Element(
            "{%s}chkData" % HOST_NS,
            nsmap={"host": HOST_NS}
        )

        for item in results:
            cd = etree.SubElement(chk_data, "{%s}cd" % HOST_NS)
            name = etree.SubElement(
                cd, "{%s}name" % HOST_NS,
                avail="1" if item.get("avail", False) else "0"
            )
            name.text = item["name"]
            if not item.get("avail") and item.get("reason"):
                etree.SubElement(cd, "{%s}reason" % HOST_NS).text = item["reason"]

        return chk_data

    def build_host_info_result(self, host: Dict[str, Any]) -> etree._Element:
        """Build host:info result data."""
        inf_data = etree.Element(
            "{%s}infData" % HOST_NS,
            nsmap={"host": HOST_NS}
        )

        # Name
        etree.SubElement(inf_data, "{%s}name" % HOST_NS).text = host["name"]

        # ROID
        etree.SubElement(inf_data, "{%s}roid" % HOST_NS).text = host["roid"]

        # Status(es)
        for status in host.get("statuses", []):
            stat_elem = etree.SubElement(
                inf_data, "{%s}status" % HOST_NS,
                s=status["s"]
            )
            if status.get("reason"):
                stat_elem.text = status["reason"]

        # IP addresses
        for addr in host.get("addrs", []):
            addr_elem = etree.SubElement(
                inf_data, "{%s}addr" % HOST_NS,
                ip=addr.get("ip", "v4")
            )
            addr_elem.text = addr["addr"]

        # Sponsoring client
        etree.SubElement(inf_data, "{%s}clID" % HOST_NS).text = host.get("clID", "")

        # Creator
        if host.get("crID"):
            etree.SubElement(inf_data, "{%s}crID" % HOST_NS).text = host["crID"]

        # Create date
        if host.get("crDate"):
            etree.SubElement(inf_data, "{%s}crDate" % HOST_NS).text = host["crDate"]

        # Updater
        if host.get("upID"):
            etree.SubElement(inf_data, "{%s}upID" % HOST_NS).text = host["upID"]

        # Update date
        if host.get("upDate"):
            etree.SubElement(inf_data, "{%s}upDate" % HOST_NS).text = host["upDate"]

        return inf_data

    def build_host_create_result(
        self,
        name: str,
        cr_date: str
    ) -> etree._Element:
        """Build host:create result data."""
        cre_data = etree.Element(
            "{%s}creData" % HOST_NS,
            nsmap={"host": HOST_NS}
        )
        etree.SubElement(cre_data, "{%s}name" % HOST_NS).text = name
        etree.SubElement(cre_data, "{%s}crDate" % HOST_NS).text = cr_date
        return cre_data

    # =========================================================================
    # Extension Response Builders
    # =========================================================================

    def build_ae_eligibility_info(
        self,
        extension_data: Dict[str, Dict[str, str]]
    ) -> Optional[etree._Element]:
        """
        Build AE eligibility extension info response.

        Args:
            extension_data: Dict of {ext_name: {field_key: value}}

        Returns:
            Extension XML element or None
        """
        if not extension_data:
            return None

        # AE Eligibility namespace
        AE_ELIGIBILITY_NS = "urn:aeda:params:xml:ns:aeEligibility-1.0"

        # Check if we have eligibility data
        ae_data = extension_data.get("aeEligibility", {})
        if not ae_data or "_uri" in ae_data and len(ae_data) == 1:
            return None

        # Get namespace URI from data or use default
        ns_uri = ae_data.pop("_uri", AE_ELIGIBILITY_NS)

        # Create extension element
        inf_data = etree.Element(
            "{%s}infData" % ns_uri,
            nsmap={"aeEligibility": ns_uri}
        )

        # Add fields in standard order
        field_order = [
            "eligibilityType",
            "eligibilityName",
            "eligibilityID",
            "eligibilityIDType",
            "registrantID",
            "registrantIDType",
            "registrantName",
            "policyReason"
        ]

        for field in field_order:
            value = ae_data.get(field)
            if value:
                etree.SubElement(inf_data, "{%s}%s" % (ns_uri, field)).text = value

        # Add any additional fields not in standard order
        for field, value in ae_data.items():
            if field not in field_order and value and not field.startswith("_"):
                etree.SubElement(inf_data, "{%s}%s" % (ns_uri, field)).text = value

        return inf_data

    def build_extensions_response(
        self,
        extension_data: Dict[str, Dict[str, str]]
    ) -> Optional[etree._Element]:
        """
        Build all extension responses.

        Args:
            extension_data: Dict of {ext_name: {field_key: value}}

        Returns:
            Extension XML element containing all extensions or None
        """
        if not extension_data:
            return None

        # Container for all extensions
        extensions = []

        # Build AE Eligibility extension
        ae_eligibility = self.build_ae_eligibility_info(extension_data)
        if ae_eligibility is not None:
            extensions.append(ae_eligibility)

        # Build other extensions as needed
        # Add more extension builders here for other types

        if not extensions:
            return None

        # If only one extension, return it directly
        if len(extensions) == 1:
            return extensions[0]

        # Multiple extensions - wrap in a container
        # (Note: EPP typically has extensions as separate children)
        # Return the first one for now, or could create wrapper
        return extensions[0]


# Global response builder instance
_builder: Optional[ResponseBuilder] = None


def initialize_response_builder(config: Dict[str, Any]) -> ResponseBuilder:
    """
    Initialize global response builder from config.

    Args:
        config: EPP configuration dictionary

    Returns:
        Initialized ResponseBuilder instance
    """
    global _builder

    _builder = ResponseBuilder(
        server_id=config.get("server_id", "EPP Server"),
        roid_suffix=config.get("roid_suffix", "AE"),
        supported_versions=config.get("supported_versions", ["1.0"]),
        supported_languages=config.get("supported_languages", ["en"]),
        supported_objects=config.get("supported_objects", [
            DOMAIN_NS, CONTACT_NS, HOST_NS
        ]),
        supported_extensions=config.get("supported_extensions", [])
    )

    return _builder


def get_response_builder() -> ResponseBuilder:
    """
    Get global response builder.

    Returns:
        ResponseBuilder instance

    Raises:
        RuntimeError: If builder not initialized
    """
    if _builder is None:
        raise RuntimeError("Response builder not initialized")
    return _builder
