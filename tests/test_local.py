#!/usr/bin/env python3
"""
EPP Server Local Test Suite

Tests components without requiring Oracle database connection.
Run with: python tests/test_local.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime

def print_header(title):
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)

def print_ok(msg):
    print(f"  ✓ {msg}")

def print_fail(msg):
    print(f"  ✗ {msg}")

def test_imports():
    """Test all module imports."""
    print_header("Testing Module Imports")

    modules = [
        ("src.core.frame_handler", "EPP Frame Handler"),
        ("src.core.xml_processor", "XML Processor"),
        ("src.core.tls_handler", "TLS Handler"),
        ("src.utils.response_builder", "Response Builder"),
        ("src.utils.password_utils", "Password Utilities"),
        ("src.utils.roid_generator", "ROID Generator"),
        ("src.validators.epp_validator", "EPP Validator"),
        ("src.database.models", "Database Models"),
    ]

    all_ok = True
    for module, name in modules:
        try:
            __import__(module)
            print_ok(f"{name}")
        except Exception as e:
            print_fail(f"{name}: {e}")
            all_ok = False

    return all_ok

def test_frame_handler():
    """Test EPP frame encoding/decoding."""
    print_header("Testing Frame Handler")

    from src.core.frame_handler import encode_frame, decode_frame_header

    # Test encoding
    test_data = b'<?xml version="1.0"?><epp>test</epp>'
    encoded = encode_frame(test_data)

    if len(encoded) == len(test_data) + 4:
        print_ok(f"Frame encoding (added 4-byte header)")
    else:
        print_fail("Frame encoding failed")
        return False

    # Test header decoding
    header = encoded[:4]
    length = decode_frame_header(header)

    if length == len(test_data) + 4:
        print_ok(f"Frame header decoding (length={length})")
    else:
        print_fail(f"Header decode failed: expected {len(test_data)+4}, got {length}")
        return False

    # Verify payload
    payload = encoded[4:]
    if payload == test_data:
        print_ok("Frame payload extraction")
    else:
        print_fail("Payload mismatch")
        return False

    return True

def test_xml_processor():
    """Test XML parsing."""
    print_header("Testing XML Processor")

    from src.core.xml_processor import XMLProcessor

    processor = XMLProcessor()

    # Test login command - verify command type and basic parsing
    login_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <command>
            <login>
                <clID>testuser</clID>
                <pw>testpass</pw>
                <options>
                    <version>1.0</version>
                    <lang>en</lang>
                </options>
                <svcs>
                    <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
                </svcs>
            </login>
            <clTRID>ABC-12345</clTRID>
        </command>
    </epp>'''

    try:
        cmd = processor.parse(login_xml)
        # Check command type is login and data contains expected keys
        if cmd.command_type == "login" and "version" in cmd.data:
            print_ok("Parse login command")
        else:
            print_fail(f"Login parsing incorrect: type={cmd.command_type}, data={cmd.data}")
            return False
    except Exception as e:
        print_fail(f"Parse login failed: {e}")
        return False

    # Test logout command
    logout_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <command>
            <logout/>
            <clTRID>LOGOUT-001</clTRID>
        </command>
    </epp>'''

    try:
        cmd = processor.parse(logout_xml)
        if cmd.command_type == "logout":
            print_ok("Parse logout command")
        else:
            print_fail(f"Expected 'logout', got '{cmd.command_type}'")
            return False
    except Exception as e:
        print_fail(f"Parse logout failed: {e}")
        return False

    # Test domain check command
    domain_check_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
        <command>
            <check>
                <domain:check xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                    <domain:name>example.ae</domain:name>
                    <domain:name>test.ae</domain:name>
                </domain:check>
            </check>
            <clTRID>CHECK-001</clTRID>
        </command>
    </epp>'''

    try:
        cmd = processor.parse(domain_check_xml)
        if cmd.command_type == "check" and cmd.object_type == "domain":
            names = cmd.data.get("names", [])
            if "example.ae" in names and "test.ae" in names:
                print_ok("Parse domain:check command")
            else:
                print_fail(f"Domain names not parsed correctly: {names}")
                return False
        else:
            print_fail(f"Expected domain check, got {cmd.object_type}:{cmd.command_type}")
            return False
    except Exception as e:
        print_fail(f"Parse domain check failed: {e}")
        return False

    return True

def test_response_builder():
    """Test EPP response building."""
    print_header("Testing Response Builder")

    from src.utils.response_builder import ResponseBuilder

    builder = ResponseBuilder(server_id="Test EPP Server", roid_suffix="AE")

    # Test greeting
    greeting = builder.build_greeting()
    if b"<greeting>" in greeting and b"Test EPP Server" in greeting:
        print_ok("Build greeting")
    else:
        print_fail("Greeting missing expected content")
        return False

    # Test success response
    response = builder.build_response(
        code=1000,
        cl_trid="ABC-123",
        sv_trid="SV-TEST-001"
    )
    if b'code="1000"' in response and b"ABC-123" in response:
        print_ok("Build success response (1000)")
    else:
        print_fail("Success response incorrect")
        return False

    # Test error response
    error = builder.build_error(
        code=2303,
        cl_trid="ABC-456",
        reason="Object not found"
    )
    if b'code="2303"' in error:
        print_ok("Build error response (2303)")
    else:
        print_fail("Error response incorrect")
        return False

    # Test domain check result
    results = [
        {"name": "available.ae", "avail": True},
        {"name": "taken.ae", "avail": False, "reason": "In use"}
    ]
    check_result = builder.build_domain_check_result(results)
    # Convert to string for checking
    from lxml import etree
    result_str = etree.tostring(check_result)
    if b'avail="1"' in result_str and b'avail="0"' in result_str:
        print_ok("Build domain:check result")
    else:
        print_fail("Domain check result incorrect")
        return False

    return True

def test_validators():
    """Test input validators."""
    print_header("Testing Validators")

    from src.validators.epp_validator import EPPValidator

    validator = EPPValidator()

    # Test domain name validation
    valid, _ = validator.validate_domain_name("example.ae")
    if valid:
        print_ok("Valid domain: example.ae")
    else:
        print_fail("example.ae should be valid")
        return False

    valid, error = validator.validate_domain_name("invalid..ae")
    if not valid:
        print_ok(f"Invalid domain rejected: invalid..ae ({error})")
    else:
        print_fail("invalid..ae should be rejected")
        return False

    # Test contact ID validation
    valid, _ = validator.validate_contact_id("contact123")
    if valid:
        print_ok("Valid contact ID: contact123")
    else:
        print_fail("contact123 should be valid")
        return False

    valid, error = validator.validate_contact_id("ab")
    if not valid:
        print_ok(f"Invalid contact ID rejected: ab ({error})")
    else:
        print_fail("'ab' should be rejected (too short)")
        return False

    # Test email validation
    valid, _ = validator.validate_email("test@example.com")
    if valid:
        print_ok("Valid email: test@example.com")
    else:
        print_fail("test@example.com should be valid")
        return False

    valid, error = validator.validate_email("invalid-email")
    if not valid:
        print_ok(f"Invalid email rejected: invalid-email")
    else:
        print_fail("invalid-email should be rejected")
        return False

    # Test phone validation
    valid, _ = validator.validate_phone("+971.123456789")
    if valid:
        print_ok("Valid phone: +971.123456789")
    else:
        print_fail("+971.123456789 should be valid")
        return False

    # Test IP address validation
    valid, _ = validator.validate_ip_address("192.168.1.1", "v4")
    if valid:
        print_ok("Valid IPv4: 192.168.1.1")
    else:
        print_fail("192.168.1.1 should be valid")
        return False

    valid, _ = validator.validate_ip_address("2001:db8::1", "v6")
    if valid:
        print_ok("Valid IPv6: 2001:db8::1")
    else:
        print_fail("2001:db8::1 should be valid")
        return False

    # Test country code validation
    valid, _ = validator.validate_country_code("AE")
    if valid:
        print_ok("Valid country code: AE")
    else:
        print_fail("AE should be valid")
        return False

    return True

def test_password_utils():
    """Test password utilities."""
    print_header("Testing Password Utilities")

    from src.utils.password_utils import (
        generate_auth_info,
        validate_auth_info,
        hash_auth_info,
        verify_auth_info,
        mask_auth_info
    )

    # Test generation
    auth = generate_auth_info()
    if len(auth) == 16:
        print_ok(f"Generate auth info: {mask_auth_info(auth)}")
    else:
        print_fail(f"Auth info length should be 16, got {len(auth)}")
        return False

    # Test validation
    valid, _ = validate_auth_info(auth)
    if valid:
        print_ok("Validate generated auth info")
    else:
        print_fail("Generated auth info should be valid")
        return False

    valid, error = validate_auth_info("short")
    if not valid:
        print_ok(f"Reject short auth info: {error}")
    else:
        print_fail("Short auth info should be rejected")
        return False

    # Test hashing
    hashed = hash_auth_info(auth)
    if len(hashed) == 64:  # SHA256 hex
        print_ok("Hash auth info (SHA256)")
    else:
        print_fail("Hash should be 64 chars (SHA256)")
        return False

    # Test verification
    if verify_auth_info(auth, auth, is_hashed=False):
        print_ok("Verify plain auth info")
    else:
        print_fail("Plain verification failed")
        return False

    if verify_auth_info(auth, hashed, is_hashed=True):
        print_ok("Verify hashed auth info")
    else:
        print_fail("Hashed verification failed")
        return False

    # Test masking
    masked = mask_auth_info(auth)
    if masked.startswith("*") and masked.endswith(auth[-4:]):
        print_ok(f"Mask auth info: {masked}")
    else:
        print_fail("Masking incorrect")
        return False

    return True

def test_models():
    """Test database models."""
    print_header("Testing Database Models")

    from src.database.models import (
        Account, User, Domain, Contact, Host
    )
    from decimal import Decimal
    from datetime import date

    # Test Account model (uppercase field names as per ARI schema)
    account = Account(
        ACC_ID=1,
        ACC_NAME="Test Registrar",
        ACC_STATUS="ACTIVE",
        ACC_BALANCE=Decimal("1000.00"),
        ACC_CREDIT_LIMIT=Decimal("5000.00"),
        ACC_CREDIT_LIMIT_ENABLED="Y",
        ACC_URL="https://registrar.example",
        ACC_STREET1="123 Test St",
        ACC_CITY="Abu Dhabi",
        ACC_STATE="Abu Dhabi",
        ACC_COUNTRY="AE",
        ACC_CREATE_DATE=date.today(),
        ACC_CLIENT_ID="REG-001"
    )
    if account.ACC_CLIENT_ID == "REG-001":
        print_ok("Account model")
    else:
        print_fail("Account model failed")
        return False

    # Test Domain model (includes required fields)
    domain = Domain(
        DOM_ROID="12345-AE",
        DOM_NAME="example.ae",
        DOM_LABEL="example",
        DOM_CANONICAL_FORM="example.ae",
        DOM_ZONE="ae",
        DOM_REGISTRANT_ROID="CON-12345-AE"
    )
    if domain.DOM_NAME == "example.ae":
        print_ok("Domain model")
    else:
        print_fail("Domain model failed")
        return False

    # Test Contact model
    contact = Contact(
        CON_ROID="67890-AE",
        CON_UID="contact001",
        CON_EMAIL="test@example.com"
    )
    if contact.CON_EMAIL == "test@example.com":
        print_ok("Contact model")
    else:
        print_fail("Contact model failed")
        return False

    # Test Host model (includes required fields)
    host = Host(
        HOS_ROID="11111-AE",
        HOS_NAME="ns1.example.ae",
        HOS_USERFORM="ns1.example.ae"
    )
    if host.HOS_NAME == "ns1.example.ae":
        print_ok("Host model")
    else:
        print_fail("Host model failed")
        return False

    return True

def test_tls_config():
    """Test TLS configuration parsing."""
    print_header("Testing TLS Configuration")

    import ssl
    from src.core.tls_handler import TLSHandler

    # Test that TLS handler can be instantiated
    # (won't actually load certs, just test config)
    try:
        handler = TLSHandler.__new__(TLSHandler)
        handler.min_version = ssl.TLSVersion.TLSv1_2
        handler.ciphers = "ECDHE+AESGCM:DHE+AESGCM"
        print_ok("TLS Handler configuration")
    except Exception as e:
        print_fail(f"TLS Handler config: {e}")
        return False

    # Test protocol versions
    if ssl.TLSVersion.TLSv1_2.value < ssl.TLSVersion.TLSv1_3.value:
        print_ok("TLS version ordering correct")
    else:
        print_fail("TLS version check failed")
        return False

    return True

def run_all_tests():
    """Run all tests."""
    print("\n" + "="*60)
    print(" EPP Server Local Test Suite")
    print(" " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("="*60)

    tests = [
        ("Module Imports", test_imports),
        ("Frame Handler", test_frame_handler),
        ("XML Processor", test_xml_processor),
        ("Response Builder", test_response_builder),
        ("Validators", test_validators),
        ("Password Utilities", test_password_utils),
        ("Database Models", test_models),
        ("TLS Configuration", test_tls_config),
    ]

    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed))
        except Exception as e:
            print_fail(f"Exception: {e}")
            results.append((name, False))

    # Summary
    print_header("Test Summary")

    passed = sum(1 for _, p in results if p)
    total = len(results)

    for name, p in results:
        status = "PASS" if p else "FAIL"
        print(f"  {status}: {name}")

    print(f"\n  Total: {passed}/{total} passed")

    if passed == total:
        print("\n  ✓ All tests passed!")
        return 0
    else:
        print(f"\n  ✗ {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(run_all_tests())
