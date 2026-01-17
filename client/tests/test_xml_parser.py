"""
Tests for EPP XML parser module.
"""

import pytest
from datetime import datetime
from epp_client.xml_parser import XMLParser
from epp_client.exceptions import EPPXMLError


class TestParseGreeting:
    """Tests for greeting parsing."""

    GREETING_XML = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <greeting>
            <svID>AE Registry EPP Server</svID>
            <svDate>2025-01-15T10:00:00Z</svDate>
            <svcMenu>
                <version>1.0</version>
                <lang>en</lang>
                <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
                <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
                <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
                <svcExtension>
                    <extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI>
                </svcExtension>
            </svcMenu>
        </greeting>
    </epp>'''

    def test_parse_greeting(self):
        """Parse server greeting."""
        greeting = XMLParser.parse_greeting(self.GREETING_XML)

        assert greeting.server_id == "AE Registry EPP Server"
        assert "1.0" in greeting.version
        assert "en" in greeting.lang
        assert "urn:ietf:params:xml:ns:domain-1.0" in greeting.obj_uris
        assert "urn:ietf:params:xml:ns:contact-1.0" in greeting.obj_uris
        assert "urn:ietf:params:xml:ns:host-1.0" in greeting.obj_uris
        assert "urn:ietf:params:xml:ns:rgp-1.0" in greeting.ext_uris


class TestParseResponse:
    """Tests for response parsing."""

    SUCCESS_RESPONSE = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <response>
            <result code="1000">
                <msg>Command completed successfully</msg>
            </result>
            <trID>
                <clTRID>TEST-001</clTRID>
                <svTRID>SV-12345</svTRID>
            </trID>
        </response>
    </epp>'''

    ERROR_RESPONSE = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <response>
            <result code="2303">
                <msg>Object does not exist</msg>
            </result>
            <trID>
                <clTRID>TEST-002</clTRID>
                <svTRID>SV-12346</svTRID>
            </trID>
        </response>
    </epp>'''

    def test_parse_success_response(self):
        """Parse successful response."""
        response = XMLParser.parse_response(self.SUCCESS_RESPONSE)

        assert response.code == 1000
        assert response.message == "Command completed successfully"
        assert response.cl_trid == "TEST-001"
        assert response.sv_trid == "SV-12345"
        assert response.success is True

    def test_parse_error_response(self):
        """Parse error response."""
        response = XMLParser.parse_response(self.ERROR_RESPONSE)

        assert response.code == 2303
        assert response.message == "Object does not exist"
        assert response.success is False


class TestParseDomainCheck:
    """Tests for domain check response parsing."""

    DOMAIN_CHECK_RESPONSE = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <response>
            <result code="1000">
                <msg>Command completed successfully</msg>
            </result>
            <resData>
                <domain:chkData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                    <domain:cd>
                        <domain:name avail="1">available.ae</domain:name>
                    </domain:cd>
                    <domain:cd>
                        <domain:name avail="0">taken.ae</domain:name>
                        <domain:reason>In use</domain:reason>
                    </domain:cd>
                </domain:chkData>
            </resData>
            <trID>
                <clTRID>TEST-003</clTRID>
                <svTRID>SV-12347</svTRID>
            </trID>
        </response>
    </epp>'''

    def test_parse_domain_check(self):
        """Parse domain check response."""
        result = XMLParser.parse_domain_check(self.DOMAIN_CHECK_RESPONSE)

        assert len(result.results) == 2

        # First domain - available
        assert result.results[0].name == "available.ae"
        assert result.results[0].available is True
        assert result.results[0].reason is None

        # Second domain - taken
        assert result.results[1].name == "taken.ae"
        assert result.results[1].available is False
        assert result.results[1].reason == "In use"

        # Helper method
        assert result.is_available("available.ae") is True
        assert result.is_available("taken.ae") is False


class TestParseDomainInfo:
    """Tests for domain info response parsing."""

    DOMAIN_INFO_RESPONSE = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <response>
            <result code="1000">
                <msg>Command completed successfully</msg>
            </result>
            <resData>
                <domain:infData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                    <domain:name>example.ae</domain:name>
                    <domain:roid>DOM-12345</domain:roid>
                    <domain:status s="ok"/>
                    <domain:status s="clientTransferProhibited"/>
                    <domain:registrant>contact123</domain:registrant>
                    <domain:contact type="admin">admin123</domain:contact>
                    <domain:contact type="tech">tech123</domain:contact>
                    <domain:ns>
                        <domain:hostObj>ns1.example.ae</domain:hostObj>
                        <domain:hostObj>ns2.example.ae</domain:hostObj>
                    </domain:ns>
                    <domain:clID>registrar1</domain:clID>
                    <domain:crID>registrar1</domain:crID>
                    <domain:crDate>2020-01-15T10:00:00Z</domain:crDate>
                    <domain:exDate>2025-01-15T10:00:00Z</domain:exDate>
                </domain:infData>
            </resData>
            <trID>
                <clTRID>TEST-004</clTRID>
                <svTRID>SV-12348</svTRID>
            </trID>
        </response>
    </epp>'''

    def test_parse_domain_info(self):
        """Parse domain info response."""
        result = XMLParser.parse_domain_info(self.DOMAIN_INFO_RESPONSE)

        assert result.name == "example.ae"
        assert result.roid == "DOM-12345"
        assert "ok" in result.status
        assert "clientTransferProhibited" in result.status
        assert result.registrant == "contact123"
        assert result.cl_id == "registrar1"

        # Check contacts
        admin_contacts = [c for c in result.contacts if c.type == "admin"]
        assert len(admin_contacts) == 1
        assert admin_contacts[0].id == "admin123"

        # Check nameservers
        assert "ns1.example.ae" in result.nameservers
        assert "ns2.example.ae" in result.nameservers


class TestParseContactInfo:
    """Tests for contact info response parsing."""

    CONTACT_INFO_RESPONSE = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <response>
            <result code="1000">
                <msg>Command completed successfully</msg>
            </result>
            <resData>
                <contact:infData xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                    <contact:id>contact123</contact:id>
                    <contact:roid>CON-12345</contact:roid>
                    <contact:status s="ok"/>
                    <contact:postalInfo type="int">
                        <contact:name>John Doe</contact:name>
                        <contact:org>Example Corp</contact:org>
                        <contact:addr>
                            <contact:street>123 Main St</contact:street>
                            <contact:city>Dubai</contact:city>
                            <contact:sp>Dubai</contact:sp>
                            <contact:pc>12345</contact:pc>
                            <contact:cc>AE</contact:cc>
                        </contact:addr>
                    </contact:postalInfo>
                    <contact:voice>+971.41234567</contact:voice>
                    <contact:email>john@example.ae</contact:email>
                    <contact:clID>registrar1</contact:clID>
                    <contact:crID>registrar1</contact:crID>
                    <contact:crDate>2020-01-15T10:00:00Z</contact:crDate>
                </contact:infData>
            </resData>
            <trID>
                <clTRID>TEST-005</clTRID>
                <svTRID>SV-12349</svTRID>
            </trID>
        </response>
    </epp>'''

    def test_parse_contact_info(self):
        """Parse contact info response."""
        result = XMLParser.parse_contact_info(self.CONTACT_INFO_RESPONSE)

        assert result.id == "contact123"
        assert result.roid == "CON-12345"
        assert "ok" in result.status
        assert result.voice == "+971.41234567"
        assert result.email == "john@example.ae"
        assert result.cl_id == "registrar1"

        # Check postal info
        assert len(result.postal_info) == 1
        postal = result.postal_info[0]
        assert postal.type == "int"
        assert postal.name == "John Doe"
        assert postal.org == "Example Corp"
        assert postal.city == "Dubai"
        assert postal.cc == "AE"


class TestParseHostInfo:
    """Tests for host info response parsing."""

    HOST_INFO_RESPONSE = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <response>
            <result code="1000">
                <msg>Command completed successfully</msg>
            </result>
            <resData>
                <host:infData xmlns:host="urn:ietf:params:xml:ns:host-1.0">
                    <host:name>ns1.example.ae</host:name>
                    <host:roid>HOST-12345</host:roid>
                    <host:status s="ok"/>
                    <host:addr ip="v4">192.0.2.1</host:addr>
                    <host:addr ip="v6">2001:db8::1</host:addr>
                    <host:clID>registrar1</host:clID>
                    <host:crID>registrar1</host:crID>
                    <host:crDate>2020-01-15T10:00:00Z</host:crDate>
                </host:infData>
            </resData>
            <trID>
                <clTRID>TEST-006</clTRID>
                <svTRID>SV-12350</svTRID>
            </trID>
        </response>
    </epp>'''

    def test_parse_host_info(self):
        """Parse host info response."""
        result = XMLParser.parse_host_info(self.HOST_INFO_RESPONSE)

        assert result.name == "ns1.example.ae"
        assert result.roid == "HOST-12345"
        assert "ok" in result.status
        assert result.cl_id == "registrar1"

        # Check addresses
        assert len(result.addresses) == 2

        ipv4 = [a for a in result.addresses if a.ip_version == "v4"]
        assert len(ipv4) == 1
        assert ipv4[0].address == "192.0.2.1"

        ipv6 = [a for a in result.addresses if a.ip_version == "v6"]
        assert len(ipv6) == 1
        assert ipv6[0].address == "2001:db8::1"


class TestParseCreateResults:
    """Tests for create response parsing."""

    DOMAIN_CREATE_RESPONSE = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <response>
            <result code="1000">
                <msg>Command completed successfully</msg>
            </result>
            <resData>
                <domain:creData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                    <domain:name>newdomain.ae</domain:name>
                    <domain:crDate>2025-01-15T10:00:00Z</domain:crDate>
                    <domain:exDate>2026-01-15T10:00:00Z</domain:exDate>
                </domain:creData>
            </resData>
            <trID>
                <clTRID>TEST-007</clTRID>
                <svTRID>SV-12351</svTRID>
            </trID>
        </response>
    </epp>'''

    CONTACT_CREATE_RESPONSE = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <response>
            <result code="1000">
                <msg>Command completed successfully</msg>
            </result>
            <resData>
                <contact:creData xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                    <contact:id>newcontact</contact:id>
                    <contact:crDate>2025-01-15T10:00:00Z</contact:crDate>
                </contact:creData>
            </resData>
            <trID>
                <clTRID>TEST-008</clTRID>
                <svTRID>SV-12352</svTRID>
            </trID>
        </response>
    </epp>'''

    def test_parse_domain_create(self):
        """Parse domain create response."""
        result = XMLParser.parse_domain_create(self.DOMAIN_CREATE_RESPONSE)

        assert result.name == "newdomain.ae"
        assert result.cr_date is not None

    def test_parse_contact_create(self):
        """Parse contact create response."""
        result = XMLParser.parse_contact_create(self.CONTACT_CREATE_RESPONSE)

        assert result.id == "newcontact"
        assert result.cr_date is not None
