"""
Tests for EPP XML builder module.
"""

import pytest
from lxml import etree
from epp_client.xml_builder import XMLBuilder
from epp_client.models import (
    DomainCreate,
    ContactCreate,
    HostCreate,
    PostalInfo,
    HostAddress,
)


def parse_xml(xml_bytes: bytes) -> etree._Element:
    """Parse XML bytes to element."""
    return etree.fromstring(xml_bytes)


def get_text(element, xpath, namespaces=None):
    """Get text from element by xpath."""
    if namespaces is None:
        namespaces = {
            "epp": "urn:ietf:params:xml:ns:epp-1.0",
            "domain": "urn:ietf:params:xml:ns:domain-1.0",
            "contact": "urn:ietf:params:xml:ns:contact-1.0",
            "host": "urn:ietf:params:xml:ns:host-1.0",
        }
    result = element.xpath(xpath, namespaces=namespaces)
    if result:
        if isinstance(result[0], str):
            return result[0]
        return result[0].text
    return None


class TestSessionCommands:
    """Tests for session command builders."""

    def test_build_hello(self):
        """Build hello command."""
        xml = XMLBuilder.build_hello()
        root = parse_xml(xml)

        # Should have <hello> element
        hello = root.find(".//{urn:ietf:params:xml:ns:epp-1.0}hello")
        assert hello is not None

    def test_build_login(self):
        """Build login command."""
        xml = XMLBuilder.build_login(
            client_id="registrar1",
            password="secret123",
            version="1.0",
            lang="en",
            obj_uris=["urn:ietf:params:xml:ns:domain-1.0"],
            ext_uris=["urn:ietf:params:xml:ns:rgp-1.0"],
            cl_trid="TEST-001",
        )
        root = parse_xml(xml)

        # Check client ID
        assert get_text(root, "//epp:clID") == "registrar1"

        # Check password
        assert get_text(root, "//epp:pw") == "secret123"

        # Check version
        assert get_text(root, "//epp:version") == "1.0"

        # Check language
        assert get_text(root, "//epp:lang") == "en"

        # Check transaction ID
        assert get_text(root, "//epp:clTRID") == "TEST-001"

    def test_build_login_with_new_password(self):
        """Build login command with password change."""
        xml = XMLBuilder.build_login(
            client_id="registrar1",
            password="oldpass",
            new_password="newpass",
            cl_trid="TEST-002",
        )
        root = parse_xml(xml)

        assert get_text(root, "//epp:pw") == "oldpass"
        assert get_text(root, "//epp:newPW") == "newpass"

    def test_build_logout(self):
        """Build logout command."""
        xml = XMLBuilder.build_logout(cl_trid="TEST-003")
        root = parse_xml(xml)

        # Should have <logout> element
        logout = root.find(".//{urn:ietf:params:xml:ns:epp-1.0}logout")
        assert logout is not None

        # Check transaction ID
        assert get_text(root, "//epp:clTRID") == "TEST-003"


class TestDomainCommands:
    """Tests for domain command builders."""

    def test_build_domain_check(self):
        """Build domain check command."""
        xml = XMLBuilder.build_domain_check(
            names=["example.ae", "test.ae"],
            cl_trid="TEST-004",
        )
        root = parse_xml(xml)

        # Get domain names
        names = root.xpath(
            "//domain:name/text()",
            namespaces={"domain": "urn:ietf:params:xml:ns:domain-1.0"}
        )
        assert "example.ae" in names
        assert "test.ae" in names

    def test_build_domain_info(self):
        """Build domain info command."""
        xml = XMLBuilder.build_domain_info(
            name="example.ae",
            hosts="all",
            cl_trid="TEST-005",
        )
        root = parse_xml(xml)

        assert get_text(root, "//domain:name") == "example.ae"

    def test_build_domain_create(self):
        """Build domain create command."""
        create_data = DomainCreate(
            name="newdomain.ae",
            registrant="contact123",
            period=2,
            period_unit="y",
            admin="admin123",
            tech="tech123",
            nameservers=["ns1.example.ae", "ns2.example.ae"],
            auth_info="auth-secret",
        )

        xml = XMLBuilder.build_domain_create(
            create_data=create_data,
            cl_trid="TEST-006",
        )
        root = parse_xml(xml)

        assert get_text(root, "//domain:name") == "newdomain.ae"
        assert get_text(root, "//domain:registrant") == "contact123"

        # Check nameservers
        ns_names = root.xpath(
            "//domain:hostObj/text()",
            namespaces={"domain": "urn:ietf:params:xml:ns:domain-1.0"}
        )
        assert "ns1.example.ae" in ns_names
        assert "ns2.example.ae" in ns_names

    def test_build_domain_delete(self):
        """Build domain delete command."""
        xml = XMLBuilder.build_domain_delete(
            name="todelete.ae",
            cl_trid="TEST-007",
        )
        root = parse_xml(xml)

        assert get_text(root, "//domain:name") == "todelete.ae"

    def test_build_domain_renew(self):
        """Build domain renew command."""
        xml = XMLBuilder.build_domain_renew(
            name="torenew.ae",
            cur_exp_date="2025-01-15",
            period=1,
            period_unit="y",
            cl_trid="TEST-008",
        )
        root = parse_xml(xml)

        assert get_text(root, "//domain:name") == "torenew.ae"
        assert get_text(root, "//domain:curExpDate") == "2025-01-15"


class TestContactCommands:
    """Tests for contact command builders."""

    def test_build_contact_check(self):
        """Build contact check command."""
        xml = XMLBuilder.build_contact_check(
            ids=["contact1", "contact2"],
            cl_trid="TEST-009",
        )
        root = parse_xml(xml)

        ids = root.xpath(
            "//contact:id/text()",
            namespaces={"contact": "urn:ietf:params:xml:ns:contact-1.0"}
        )
        assert "contact1" in ids
        assert "contact2" in ids

    def test_build_contact_create(self):
        """Build contact create command."""
        postal_info = PostalInfo(
            name="John Doe",
            city="Dubai",
            cc="AE",
            type="int",
            org="Example Corp",
            street=["123 Main St", "Suite 100"],
            sp="Dubai",
            pc="12345",
        )

        create_data = ContactCreate(
            id="newcontact",
            email="john@example.ae",
            postal_info=postal_info,
            voice="+971.41234567",
            fax="+971.41234568",
            auth_info="contact-auth",
        )

        xml = XMLBuilder.build_contact_create(
            create_data=create_data,
            cl_trid="TEST-010",
        )
        root = parse_xml(xml)

        assert get_text(root, "//contact:id") == "newcontact"
        assert get_text(root, "//contact:email") == "john@example.ae"
        assert get_text(root, "//contact:voice") == "+971.41234567"


class TestHostCommands:
    """Tests for host command builders."""

    def test_build_host_check(self):
        """Build host check command."""
        xml = XMLBuilder.build_host_check(
            names=["ns1.example.ae", "ns2.example.ae"],
            cl_trid="TEST-011",
        )
        root = parse_xml(xml)

        names = root.xpath(
            "//host:name/text()",
            namespaces={"host": "urn:ietf:params:xml:ns:host-1.0"}
        )
        assert "ns1.example.ae" in names
        assert "ns2.example.ae" in names

    def test_build_host_create(self):
        """Build host create command."""
        create_data = HostCreate(
            name="ns1.newdomain.ae",
            addresses=[
                HostAddress(address="192.0.2.1", ip_version="v4"),
                HostAddress(address="2001:db8::1", ip_version="v6"),
            ],
        )

        xml = XMLBuilder.build_host_create(
            create_data=create_data,
            cl_trid="TEST-012",
        )
        root = parse_xml(xml)

        assert get_text(root, "//host:name") == "ns1.newdomain.ae"

        # Check IPv4 address
        ipv4 = root.xpath(
            "//host:addr[@ip='v4']/text()",
            namespaces={"host": "urn:ietf:params:xml:ns:host-1.0"}
        )
        assert "192.0.2.1" in ipv4

        # Check IPv6 address
        ipv6 = root.xpath(
            "//host:addr[@ip='v6']/text()",
            namespaces={"host": "urn:ietf:params:xml:ns:host-1.0"}
        )
        assert "2001:db8::1" in ipv6


class TestPollCommands:
    """Tests for poll command builders."""

    def test_build_poll_request(self):
        """Build poll request command."""
        xml = XMLBuilder.build_poll_request(cl_trid="TEST-013")
        root = parse_xml(xml)

        poll = root.find(".//{urn:ietf:params:xml:ns:epp-1.0}poll")
        assert poll is not None
        assert poll.get("op") == "req"

    def test_build_poll_ack(self):
        """Build poll acknowledge command."""
        xml = XMLBuilder.build_poll_ack(
            msg_id="12345",
            cl_trid="TEST-014",
        )
        root = parse_xml(xml)

        poll = root.find(".//{urn:ietf:params:xml:ns:epp-1.0}poll")
        assert poll is not None
        assert poll.get("op") == "ack"
        assert poll.get("msgID") == "12345"
