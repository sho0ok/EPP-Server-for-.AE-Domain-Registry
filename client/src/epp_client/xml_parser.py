"""
EPP XML Parser

Parses EPP XML responses per RFC 5730-5733.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from lxml import etree

from epp_client.exceptions import EPPXMLError
from epp_client.models import (
    Greeting,
    EPPResponse,
    DomainCheckResult,
    DomainCheckItem,
    DomainInfo,
    DomainContact,
    DomainEligibilityInfo,
    DomainCreateResult,
    DomainRenewResult,
    DomainTransferResult,
    ContactCheckResult,
    ContactCheckItem,
    ContactInfo,
    PostalInfoData,
    ContactCreateResult,
    HostCheckResult,
    HostCheckItem,
    HostInfo,
    HostAddress,
    HostCreateResult,
    PollMessage,
)

logger = logging.getLogger("epp.parser")

# Namespaces
NS = {
    "epp": "urn:ietf:params:xml:ns:epp-1.0",
    "domain": "urn:ietf:params:xml:ns:domain-1.0",
    "contact": "urn:ietf:params:xml:ns:contact-1.0",
    "host": "urn:ietf:params:xml:ns:host-1.0",
    "aeEligibility": "urn:aeda:params:xml:ns:aeEligibility-1.0",
}

# Secure parser
_parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    remove_blank_text=True,
)


def _parse_datetime(text: str) -> Optional[datetime]:
    """Parse ISO datetime string."""
    if not text:
        return None
    try:
        text = text.replace("Z", "+00:00")
        if "." in text:
            return datetime.fromisoformat(text.split(".")[0])
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _find_text(elem: etree._Element, path: str, default: str = None) -> Optional[str]:
    """Find element and return text."""
    found = elem.find(path, NS)
    if found is not None and found.text:
        return found.text
    return default


def _find_all_text(elem: etree._Element, path: str) -> List[str]:
    """Find all elements and return their text."""
    return [e.text for e in elem.findall(path, NS) if e.text]


def _parse_xml(xml_data: bytes) -> etree._Element:
    """Parse XML with secure parser."""
    try:
        return etree.fromstring(xml_data, _parser)
    except etree.XMLSyntaxError as e:
        raise EPPXMLError(f"XML parse error: {e}")


class XMLParser:
    """
    Parses EPP XML responses.

    All methods are static and return structured response objects.
    """

    @staticmethod
    def parse_greeting(xml_data: bytes) -> Greeting:
        """
        Parse EPP greeting.

        Args:
            xml_data: Raw XML bytes

        Returns:
            Greeting object
        """
        root = _parse_xml(xml_data)

        greeting = root.find("epp:greeting", NS)
        if greeting is None:
            raise EPPXMLError("No greeting element found")

        return Greeting(
            server_id=_find_text(greeting, "epp:svID", ""),
            server_date=_parse_datetime(_find_text(greeting, "epp:svDate")),
            version=_find_all_text(greeting, "epp:svcMenu/epp:version"),
            lang=_find_all_text(greeting, "epp:svcMenu/epp:lang"),
            obj_uris=_find_all_text(greeting, "epp:svcMenu/epp:objURI"),
            ext_uris=_find_all_text(greeting, "epp:svcMenu/epp:svcExtension/epp:extURI"),
        )

    @staticmethod
    def parse_response(xml_data: bytes) -> EPPResponse:
        """
        Parse EPP response.

        Args:
            xml_data: Raw XML bytes

        Returns:
            EPPResponse object
        """
        root = _parse_xml(xml_data)

        response = root.find("epp:response", NS)
        if response is None:
            raise EPPXMLError("No response element found")

        # Get result
        result = response.find("epp:result", NS)
        if result is None:
            raise EPPXMLError("No result element found")

        code = int(result.get("code", "2400"))
        msg = _find_text(result, "epp:msg", "Unknown error")

        # Get transaction IDs
        trn_id = response.find("epp:trID", NS)
        cl_trid = None
        sv_trid = None
        if trn_id is not None:
            cl_trid = _find_text(trn_id, "epp:clTRID")
            sv_trid = _find_text(trn_id, "epp:svTRID")

        return EPPResponse(
            code=code,
            message=msg,
            cl_trid=cl_trid,
            sv_trid=sv_trid,
            raw_xml=xml_data.decode("utf-8", errors="replace"),
        )

    @staticmethod
    def parse_domain_check(xml_data: bytes) -> DomainCheckResult:
        """Parse domain check response."""
        root = _parse_xml(xml_data)

        check_data = root.find(".//domain:chkData", NS)
        if check_data is None:
            raise EPPXMLError("No domain:chkData element found")

        results = []
        for cd in check_data.findall("domain:cd", NS):
            name_elem = cd.find("domain:name", NS)
            if name_elem is not None:
                name = name_elem.text
                avail = name_elem.get("avail", "0") in ("1", "true")
                reason = _find_text(cd, "domain:reason")
                results.append(DomainCheckItem(name=name, available=avail, reason=reason))

        return DomainCheckResult(results=results)

    @staticmethod
    def parse_domain_info(xml_data: bytes) -> DomainInfo:
        """Parse domain info response."""
        root = _parse_xml(xml_data)

        info_data = root.find(".//domain:infData", NS)
        if info_data is None:
            raise EPPXMLError("No domain:infData element found")

        # Status
        statuses = []
        for s in info_data.findall("domain:status", NS):
            statuses.append(s.get("s", ""))

        # Contacts
        contacts = []
        for c in info_data.findall("domain:contact", NS):
            contacts.append(DomainContact(
                id=c.text,
                type=c.get("type", "")
            ))

        # Nameservers
        ns = info_data.find("domain:ns", NS)
        nameservers = []
        if ns is not None:
            nameservers = _find_all_text(ns, "domain:hostObj")
            if not nameservers:
                nameservers = _find_all_text(ns, "domain:hostAttr/domain:hostName")

        # Hosts (subordinate)
        hosts = _find_all_text(info_data, "domain:host")

        # Auth info
        auth_info = _find_text(info_data, "domain:authInfo/domain:pw")

        # Parse extension data (AE eligibility)
        eligibility = XMLParser._parse_ae_eligibility_extension(root)

        return DomainInfo(
            name=_find_text(info_data, "domain:name", ""),
            roid=_find_text(info_data, "domain:roid", ""),
            status=statuses,
            registrant=_find_text(info_data, "domain:registrant"),
            contacts=contacts,
            nameservers=nameservers,
            hosts=hosts,
            cl_id=_find_text(info_data, "domain:clID", ""),
            cr_id=_find_text(info_data, "domain:crID"),
            cr_date=_parse_datetime(_find_text(info_data, "domain:crDate")),
            up_id=_find_text(info_data, "domain:upID"),
            up_date=_parse_datetime(_find_text(info_data, "domain:upDate")),
            ex_date=_parse_datetime(_find_text(info_data, "domain:exDate")),
            tr_date=_parse_datetime(_find_text(info_data, "domain:trDate")),
            auth_info=auth_info,
            eligibility=eligibility,
        )

    @staticmethod
    def _parse_ae_eligibility_extension(root: etree._Element) -> Optional[DomainEligibilityInfo]:
        """Parse AE eligibility extension from domain info response."""
        # Look for extension element
        extension = root.find(".//epp:extension", NS)
        if extension is None:
            return None

        # Look for AE eligibility info in extension
        ae_info = extension.find("aeEligibility:infData", NS)
        if ae_info is None:
            return None

        # Parse policy reason as int if present
        policy_reason_text = _find_text(ae_info, "aeEligibility:policyReason")
        policy_reason = None
        if policy_reason_text:
            try:
                policy_reason = int(policy_reason_text)
            except ValueError:
                pass

        return DomainEligibilityInfo(
            eligibility_type=_find_text(ae_info, "aeEligibility:eligibilityType"),
            eligibility_name=_find_text(ae_info, "aeEligibility:eligibilityName"),
            eligibility_id=_find_text(ae_info, "aeEligibility:eligibilityID"),
            eligibility_id_type=_find_text(ae_info, "aeEligibility:eligibilityIDType"),
            policy_reason=policy_reason,
            registrant_id=_find_text(ae_info, "aeEligibility:registrantID"),
            registrant_id_type=_find_text(ae_info, "aeEligibility:registrantIDType"),
            registrant_name=_find_text(ae_info, "aeEligibility:registrantName"),
        )

    @staticmethod
    def parse_domain_create(xml_data: bytes) -> DomainCreateResult:
        """Parse domain create response."""
        root = _parse_xml(xml_data)

        create_data = root.find(".//domain:creData", NS)
        if create_data is None:
            raise EPPXMLError("No domain:creData element found")

        return DomainCreateResult(
            name=_find_text(create_data, "domain:name", ""),
            cr_date=_parse_datetime(_find_text(create_data, "domain:crDate")),
            ex_date=_parse_datetime(_find_text(create_data, "domain:exDate")),
        )

    @staticmethod
    def parse_domain_renew(xml_data: bytes) -> DomainRenewResult:
        """Parse domain renew response."""
        root = _parse_xml(xml_data)

        renew_data = root.find(".//domain:renData", NS)
        if renew_data is None:
            raise EPPXMLError("No domain:renData element found")

        return DomainRenewResult(
            name=_find_text(renew_data, "domain:name", ""),
            ex_date=_parse_datetime(_find_text(renew_data, "domain:exDate")),
        )

    @staticmethod
    def parse_domain_transfer(xml_data: bytes) -> DomainTransferResult:
        """Parse domain transfer response."""
        root = _parse_xml(xml_data)

        trn_data = root.find(".//domain:trnData", NS)
        if trn_data is None:
            raise EPPXMLError("No domain:trnData element found")

        return DomainTransferResult(
            name=_find_text(trn_data, "domain:name", ""),
            tr_status=_find_text(trn_data, "domain:trStatus", ""),
            re_id=_find_text(trn_data, "domain:reID", ""),
            re_date=_parse_datetime(_find_text(trn_data, "domain:reDate")),
            ac_id=_find_text(trn_data, "domain:acID", ""),
            ac_date=_parse_datetime(_find_text(trn_data, "domain:acDate")),
            ex_date=_parse_datetime(_find_text(trn_data, "domain:exDate")),
        )

    @staticmethod
    def parse_contact_check(xml_data: bytes) -> ContactCheckResult:
        """Parse contact check response."""
        root = _parse_xml(xml_data)

        check_data = root.find(".//contact:chkData", NS)
        if check_data is None:
            raise EPPXMLError("No contact:chkData element found")

        results = []
        for cd in check_data.findall("contact:cd", NS):
            id_elem = cd.find("contact:id", NS)
            if id_elem is not None:
                id = id_elem.text
                avail = id_elem.get("avail", "0") in ("1", "true")
                reason = _find_text(cd, "contact:reason")
                results.append(ContactCheckItem(id=id, available=avail, reason=reason))

        return ContactCheckResult(results=results)

    @staticmethod
    def parse_contact_info(xml_data: bytes) -> ContactInfo:
        """Parse contact info response."""
        root = _parse_xml(xml_data)

        info_data = root.find(".//contact:infData", NS)
        if info_data is None:
            raise EPPXMLError("No contact:infData element found")

        # Status
        statuses = []
        for s in info_data.findall("contact:status", NS):
            statuses.append(s.get("s", ""))

        # Postal info
        postal_infos = []
        for pi in info_data.findall("contact:postalInfo", NS):
            streets = _find_all_text(pi, "contact:addr/contact:street")
            postal_infos.append(PostalInfoData(
                type=pi.get("type", "int"),
                name=_find_text(pi, "contact:name"),
                org=_find_text(pi, "contact:org"),
                street=streets,
                city=_find_text(pi, "contact:addr/contact:city"),
                sp=_find_text(pi, "contact:addr/contact:sp"),
                pc=_find_text(pi, "contact:addr/contact:pc"),
                cc=_find_text(pi, "contact:addr/contact:cc"),
            ))

        # Voice
        voice_elem = info_data.find("contact:voice", NS)
        voice = voice_elem.text if voice_elem is not None else None
        voice_ext = voice_elem.get("x") if voice_elem is not None else None

        # Fax
        fax_elem = info_data.find("contact:fax", NS)
        fax = fax_elem.text if fax_elem is not None else None
        fax_ext = fax_elem.get("x") if fax_elem is not None else None

        # Auth info
        auth_info = _find_text(info_data, "contact:authInfo/contact:pw")

        return ContactInfo(
            id=_find_text(info_data, "contact:id", ""),
            roid=_find_text(info_data, "contact:roid", ""),
            status=statuses,
            postal_info=postal_infos,
            voice=voice,
            voice_ext=voice_ext,
            fax=fax,
            fax_ext=fax_ext,
            email=_find_text(info_data, "contact:email"),
            cl_id=_find_text(info_data, "contact:clID", ""),
            cr_id=_find_text(info_data, "contact:crID"),
            cr_date=_parse_datetime(_find_text(info_data, "contact:crDate")),
            up_id=_find_text(info_data, "contact:upID"),
            up_date=_parse_datetime(_find_text(info_data, "contact:upDate")),
            tr_date=_parse_datetime(_find_text(info_data, "contact:trDate")),
            auth_info=auth_info,
        )

    @staticmethod
    def parse_contact_create(xml_data: bytes) -> ContactCreateResult:
        """Parse contact create response."""
        root = _parse_xml(xml_data)

        create_data = root.find(".//contact:creData", NS)
        if create_data is None:
            raise EPPXMLError("No contact:creData element found")

        return ContactCreateResult(
            id=_find_text(create_data, "contact:id", ""),
            cr_date=_parse_datetime(_find_text(create_data, "contact:crDate")),
        )

    @staticmethod
    def parse_host_check(xml_data: bytes) -> HostCheckResult:
        """Parse host check response."""
        root = _parse_xml(xml_data)

        check_data = root.find(".//host:chkData", NS)
        if check_data is None:
            raise EPPXMLError("No host:chkData element found")

        results = []
        for cd in check_data.findall("host:cd", NS):
            name_elem = cd.find("host:name", NS)
            if name_elem is not None:
                name = name_elem.text
                avail = name_elem.get("avail", "0") in ("1", "true")
                reason = _find_text(cd, "host:reason")
                results.append(HostCheckItem(name=name, available=avail, reason=reason))

        return HostCheckResult(results=results)

    @staticmethod
    def parse_host_info(xml_data: bytes) -> HostInfo:
        """Parse host info response."""
        root = _parse_xml(xml_data)

        info_data = root.find(".//host:infData", NS)
        if info_data is None:
            raise EPPXMLError("No host:infData element found")

        # Status
        statuses = []
        for s in info_data.findall("host:status", NS):
            statuses.append(s.get("s", ""))

        # Addresses
        addresses = []
        for addr in info_data.findall("host:addr", NS):
            addresses.append(HostAddress(
                address=addr.text,
                ip_version=addr.get("ip", "v4")
            ))

        return HostInfo(
            name=_find_text(info_data, "host:name", ""),
            roid=_find_text(info_data, "host:roid", ""),
            status=statuses,
            addresses=addresses,
            cl_id=_find_text(info_data, "host:clID", ""),
            cr_id=_find_text(info_data, "host:crID"),
            cr_date=_parse_datetime(_find_text(info_data, "host:crDate")),
            up_id=_find_text(info_data, "host:upID"),
            up_date=_parse_datetime(_find_text(info_data, "host:upDate")),
            tr_date=_parse_datetime(_find_text(info_data, "host:trDate")),
        )

    @staticmethod
    def parse_host_create(xml_data: bytes) -> HostCreateResult:
        """Parse host create response."""
        root = _parse_xml(xml_data)

        create_data = root.find(".//host:creData", NS)
        if create_data is None:
            raise EPPXMLError("No host:creData element found")

        return HostCreateResult(
            name=_find_text(create_data, "host:name", ""),
            cr_date=_parse_datetime(_find_text(create_data, "host:crDate")),
        )

    @staticmethod
    def parse_poll_message(xml_data: bytes) -> Optional[PollMessage]:
        """Parse poll message response."""
        root = _parse_xml(xml_data)

        msg_q = root.find(".//epp:msgQ", NS)
        if msg_q is None:
            return None

        return PollMessage(
            id=msg_q.get("id", ""),
            count=int(msg_q.get("count", "0")),
            qdate=_parse_datetime(_find_text(msg_q, "epp:qDate")),
            message=_find_text(msg_q, "epp:msg", ""),
        )
