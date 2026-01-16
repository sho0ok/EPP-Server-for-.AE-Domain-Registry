#!/usr/bin/env python3
"""
Integration tests for EPP Client.

These tests verify the client components work together correctly
without requiring an actual EPP server connection.
"""

import sys
sys.path.insert(0, 'src')

from epp_client.framing import encode_frame, decode_frame_header, FrameReader, FrameWriter
from epp_client.xml_builder import XMLBuilder
from epp_client.xml_parser import XMLParser
from epp_client.models import DomainCreate, ContactCreate, HostCreate, PostalInfo, HostAddress
from epp_client.exceptions import EPPError, EPPXMLError


def test_framing():
    """Test EPP frame encoding/decoding."""
    print("\n=== Testing Framing ===")

    # Test encode
    data = b'<?xml version="1.0"?><epp/>'
    frame = encode_frame(data)
    print(f"  Original: {len(data)} bytes")
    print(f"  Framed: {len(frame)} bytes")

    # Test decode header
    length = decode_frame_header(frame[:4])
    assert length == len(data) + 4
    print(f"  Decoded length: {length} (correct)")

    # Test roundtrip
    payload = frame[4:]
    assert payload == data
    print("  Roundtrip: PASS")

    print("  Framing tests: ALL PASS")


def test_xml_builder():
    """Test XML command building."""
    print("\n=== Testing XML Builder ===")

    # Hello
    hello = XMLBuilder.build_hello()
    assert b'<epp' in hello
    assert b'hello' in hello
    print("  build_hello: PASS")

    # Login
    login = XMLBuilder.build_login(
        client_id="registrar1",
        password="secret123",
        version="1.0",
        lang="en",
        cl_trid="TEST-001"
    )
    assert b'clID' in login
    assert b'registrar1' in login
    assert b'secret123' in login
    assert b'TEST-001' in login
    print("  build_login: PASS")

    # Logout
    logout = XMLBuilder.build_logout(cl_trid="TEST-002")
    assert b'logout' in logout
    print("  build_logout: PASS")

    # Domain check
    domain_check = XMLBuilder.build_domain_check(
        names=["example.ae", "test.ae"],
        cl_trid="TEST-003"
    )
    assert b'example.ae' in domain_check
    assert b'test.ae' in domain_check
    print("  build_domain_check: PASS")

    # Domain info
    domain_info = XMLBuilder.build_domain_info(
        name="example.ae",
        cl_trid="TEST-004"
    )
    assert b'example.ae' in domain_info
    print("  build_domain_info: PASS")

    # Domain create
    create_data = DomainCreate(
        name="newdomain.ae",
        registrant="contact123",
        period=1,
        admin="admin123",
        tech="tech123",
        nameservers=["ns1.example.ae", "ns2.example.ae"],
        auth_info="secret-auth"
    )
    domain_create = XMLBuilder.build_domain_create(create_data, cl_trid="TEST-005")
    assert b'newdomain.ae' in domain_create
    assert b'contact123' in domain_create
    assert b'ns1.example.ae' in domain_create
    print("  build_domain_create: PASS")

    # Contact check
    contact_check = XMLBuilder.build_contact_check(
        ids=["contact1", "contact2"],
        cl_trid="TEST-006"
    )
    assert b'contact1' in contact_check
    print("  build_contact_check: PASS")

    # Contact create
    postal_info = PostalInfo(
        name="John Doe",
        city="Dubai",
        cc="AE",
        type="int"
    )
    contact_data = ContactCreate(
        id="newcontact",
        email="john@example.ae",
        postal_info=postal_info,
        voice="+971.41234567"
    )
    contact_create = XMLBuilder.build_contact_create(contact_data, cl_trid="TEST-007")
    assert b'newcontact' in contact_create
    assert b'John Doe' in contact_create
    assert b'Dubai' in contact_create
    print("  build_contact_create: PASS")

    # Host check
    host_check = XMLBuilder.build_host_check(
        names=["ns1.example.ae", "ns2.example.ae"],
        cl_trid="TEST-008"
    )
    assert b'ns1.example.ae' in host_check
    print("  build_host_check: PASS")

    # Host create
    host_data = HostCreate(
        name="ns1.newdomain.ae",
        addresses=[
            HostAddress(address="192.0.2.1", ip_version="v4"),
            HostAddress(address="2001:db8::1", ip_version="v6")
        ]
    )
    host_create = XMLBuilder.build_host_create(host_data, cl_trid="TEST-009")
    assert b'ns1.newdomain.ae' in host_create
    assert b'192.0.2.1' in host_create
    print("  build_host_create: PASS")

    # Poll
    poll_req = XMLBuilder.build_poll_request(cl_trid="TEST-010")
    assert b'poll' in poll_req
    assert b'op="req"' in poll_req
    print("  build_poll_request: PASS")

    poll_ack = XMLBuilder.build_poll_ack(msg_id="12345", cl_trid="TEST-011")
    assert b'poll' in poll_ack
    assert b'op="ack"' in poll_ack
    assert b'msgID="12345"' in poll_ack
    print("  build_poll_ack: PASS")

    print("  XML Builder tests: ALL PASS")


def test_xml_parser():
    """Test XML response parsing."""
    print("\n=== Testing XML Parser ===")

    # Greeting
    greeting_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
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
            </svcMenu>
        </greeting>
    </epp>'''

    greeting = XMLParser.parse_greeting(greeting_xml)
    assert greeting.server_id == "AE Registry EPP Server"
    assert "1.0" in greeting.version
    assert "en" in greeting.lang
    assert len(greeting.obj_uris) == 3
    print("  parse_greeting: PASS")

    # Success response
    success_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
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

    response = XMLParser.parse_response(success_xml)
    assert response.code == 1000
    assert response.success == True
    assert response.cl_trid == "TEST-001"
    assert response.sv_trid == "SV-12345"
    print("  parse_response (success): PASS")

    # Error response
    error_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
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

    response = XMLParser.parse_response(error_xml)
    assert response.code == 2303
    assert response.success == False
    print("  parse_response (error): PASS")

    # Domain check response
    domain_check_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
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

    result = XMLParser.parse_domain_check(domain_check_xml)
    assert len(result.results) == 2
    assert result.results[0].name == "available.ae"
    assert result.results[0].available == True
    assert result.results[1].name == "taken.ae"
    assert result.results[1].available == False
    assert result.results[1].reason == "In use"
    assert result.is_available("available.ae") == True
    assert result.is_available("taken.ae") == False
    print("  parse_domain_check: PASS")

    # Domain info response
    domain_info_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
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
                    <domain:registrant>contact123</domain:registrant>
                    <domain:contact type="admin">admin123</domain:contact>
                    <domain:contact type="tech">tech123</domain:contact>
                    <domain:ns>
                        <domain:hostObj>ns1.example.ae</domain:hostObj>
                        <domain:hostObj>ns2.example.ae</domain:hostObj>
                    </domain:ns>
                    <domain:clID>registrar1</domain:clID>
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

    info = XMLParser.parse_domain_info(domain_info_xml)
    assert info.name == "example.ae"
    assert info.roid == "DOM-12345"
    assert info.registrant == "contact123"
    assert info.cl_id == "registrar1"
    assert "ns1.example.ae" in info.nameservers
    assert len(info.contacts) == 2
    print("  parse_domain_info: PASS")

    # Contact check response
    contact_check_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <response>
            <result code="1000">
                <msg>Command completed successfully</msg>
            </result>
            <resData>
                <contact:chkData xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                    <contact:cd>
                        <contact:id avail="1">newcontact</contact:id>
                    </contact:cd>
                    <contact:cd>
                        <contact:id avail="0">existingcontact</contact:id>
                    </contact:cd>
                </contact:chkData>
            </resData>
            <trID>
                <clTRID>TEST-005</clTRID>
                <svTRID>SV-12349</svTRID>
            </trID>
        </response>
    </epp>'''

    result = XMLParser.parse_contact_check(contact_check_xml)
    assert len(result.results) == 2
    assert result.is_available("newcontact") == True
    assert result.is_available("existingcontact") == False
    print("  parse_contact_check: PASS")

    # Host check response
    host_check_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <response>
            <result code="1000">
                <msg>Command completed successfully</msg>
            </result>
            <resData>
                <host:chkData xmlns:host="urn:ietf:params:xml:ns:host-1.0">
                    <host:cd>
                        <host:name avail="1">ns1.newdomain.ae</host:name>
                    </host:cd>
                    <host:cd>
                        <host:name avail="0">ns1.example.ae</host:name>
                    </host:cd>
                </host:chkData>
            </resData>
            <trID>
                <clTRID>TEST-006</clTRID>
                <svTRID>SV-12350</svTRID>
            </trID>
        </response>
    </epp>'''

    result = XMLParser.parse_host_check(host_check_xml)
    assert len(result.results) == 2
    assert result.is_available("ns1.newdomain.ae") == True
    assert result.is_available("ns1.example.ae") == False
    print("  parse_host_check: PASS")

    # Host info response
    host_info_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
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
                    <host:crDate>2020-01-15T10:00:00Z</host:crDate>
                </host:infData>
            </resData>
            <trID>
                <clTRID>TEST-007</clTRID>
                <svTRID>SV-12351</svTRID>
            </trID>
        </response>
    </epp>'''

    info = XMLParser.parse_host_info(host_info_xml)
    assert info.name == "ns1.example.ae"
    assert info.roid == "HOST-12345"
    assert len(info.addresses) == 2
    ipv4 = [a for a in info.addresses if a.ip_version == "v4"]
    assert ipv4[0].address == "192.0.2.1"
    print("  parse_host_info: PASS")

    print("  XML Parser tests: ALL PASS")


def test_models():
    """Test data models."""
    print("\n=== Testing Models ===")

    from epp_client.models import EPPResponse, DomainCheckResult, DomainCheckItem

    # Test EPPResponse.success property
    success_response = EPPResponse(code=1000, message="OK")
    assert success_response.success == True

    pending_response = EPPResponse(code=1001, message="Pending")
    assert pending_response.success == True

    error_response = EPPResponse(code=2000, message="Error")
    assert error_response.success == False

    print("  EPPResponse.success: PASS")

    # Test DomainCheckResult.is_available
    result = DomainCheckResult(results=[
        DomainCheckItem(name="available.ae", available=True),
        DomainCheckItem(name="taken.ae", available=False),
    ])
    assert result.is_available("available.ae") == True
    assert result.is_available("taken.ae") == False
    assert result.is_available("unknown.ae") == False
    print("  DomainCheckResult.is_available: PASS")

    print("  Model tests: ALL PASS")


def test_exceptions():
    """Test exception hierarchy."""
    print("\n=== Testing Exceptions ===")

    from epp_client.exceptions import (
        EPPError,
        EPPConnectionError,
        EPPAuthenticationError,
        EPPCommandError,
        EPPObjectNotFound,
        EPPObjectExists,
    )

    # Test inheritance
    assert issubclass(EPPConnectionError, EPPError)
    assert issubclass(EPPAuthenticationError, EPPError)
    assert issubclass(EPPCommandError, EPPError)
    assert issubclass(EPPObjectNotFound, EPPCommandError)
    assert issubclass(EPPObjectExists, EPPCommandError)
    print("  Exception hierarchy: PASS")

    # Test exception with code
    try:
        raise EPPCommandError("Test error", code=2303)
    except EPPCommandError as e:
        assert e.code == 2303
        assert "Test error" in str(e)
    print("  EPPCommandError with code: PASS")

    print("  Exception tests: ALL PASS")


def test_client_import():
    """Test client class imports."""
    print("\n=== Testing Client Imports ===")

    from epp_client import EPPClient, AsyncEPPClient, EPPConnectionPool, PoolConfig

    # Verify classes are callable
    assert callable(EPPClient)
    assert callable(AsyncEPPClient)
    assert callable(EPPConnectionPool)
    assert callable(PoolConfig)
    print("  Import EPPClient: PASS")
    print("  Import AsyncEPPClient: PASS")
    print("  Import EPPConnectionPool: PASS")
    print("  Import PoolConfig: PASS")

    print("  Client import tests: ALL PASS")


def main():
    """Run all tests."""
    print("=" * 60)
    print("EPP Client Toolkit - Integration Tests")
    print("=" * 60)

    try:
        test_framing()
        test_xml_builder()
        test_xml_parser()
        test_models()
        test_exceptions()
        test_client_import()

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED!")
        print("=" * 60)
        return 0

    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
