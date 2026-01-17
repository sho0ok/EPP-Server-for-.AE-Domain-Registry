#!/usr/bin/env python3
"""
Comprehensive Command Test

Tests ALL EPP client commands including IDN support.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from epp_client import EPPClient

CERT_DIR = "/home/alhammadi/Downloads/ARI/test-certs"


def create_client():
    """Create test client."""
    return EPPClient(
        host="localhost",
        port=7700,
        cert_file=f"{CERT_DIR}/client.crt",
        key_file=f"{CERT_DIR}/client.key",
        ca_file=f"{CERT_DIR}/ca.crt",
        timeout=30,
    )


def test_session_commands():
    """Test session commands: hello, login, logout."""
    print("\n" + "=" * 60)
    print("SESSION COMMANDS")
    print("=" * 60)

    client = create_client()

    try:
        # Connect (receives greeting)
        print("\n[connect] Connecting...")
        greeting = client.connect()
        print(f"  ✓ Server: {greeting.server_id}")

        # Hello
        print("\n[hello] Sending hello...")
        greeting2 = client.hello()
        print(f"  ✓ Server: {greeting2.server_id}")

        # Login
        print("\n[login] Logging in...")
        response = client.login("testregistrar", "testpassword")
        print(f"  ✓ Code: {response.code} - {response.message}")

        # Logout
        print("\n[logout] Logging out...")
        response = client.logout()
        print(f"  ✓ Code: {response.code} - {response.message}")

        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False
    finally:
        client.disconnect()


def test_domain_commands():
    """Test domain commands."""
    print("\n" + "=" * 60)
    print("DOMAIN COMMANDS")
    print("=" * 60)

    client = create_client()

    try:
        client.connect()
        client.login("testregistrar", "testpassword")

        # Domain Check - ASCII
        print("\n[domain:check] ASCII domains...")
        result = client.domain_check(["example.ae", "test.ae", "taken-domain.ae"])
        for item in result.results:
            status = "✓ Available" if item.available else "✗ Taken"
            print(f"  {item.name}: {status}")

        # Domain Check - IDN Arabic
        print("\n[domain:check] IDN Arabic domains (.امارات)...")
        result = client.domain_check(["مثال.امارات", "تجربة.امارات", "taken-اختبار.امارات"])
        for item in result.results:
            status = "✓ Available" if item.available else "✗ Taken"
            print(f"  {item.name}: {status}")

        # Domain Check - Mixed
        print("\n[domain:check] Mixed ASCII and Arabic...")
        result = client.domain_check(["example.ae", "مثال.امارات"])
        for item in result.results:
            status = "✓ Available" if item.available else "✗ Taken"
            print(f"  {item.name}: {status}")

        # Domain Info
        print("\n[domain:info] Getting domain info...")
        info = client.domain_info("example.ae")
        print(f"  ✓ Name: {info.name}")
        print(f"  ✓ ROID: {info.roid}")
        print(f"  ✓ Status: {info.status}")
        print(f"  ✓ Registrant: {info.registrant}")
        print(f"  ✓ Nameservers: {info.nameservers}")

        client.logout()
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.disconnect()


def test_contact_commands():
    """Test contact commands."""
    print("\n" + "=" * 60)
    print("CONTACT COMMANDS")
    print("=" * 60)

    client = create_client()

    try:
        client.connect()
        client.login("testregistrar", "testpassword")

        # Contact Check
        print("\n[contact:check] Checking contacts...")
        result = client.contact_check(["contact1", "contact2", "taken-contact"])
        for item in result.results:
            status = "✓ Available" if item.available else "✗ Taken"
            print(f"  {item.id}: {status}")

        # Contact Check - Arabic IDs
        print("\n[contact:check] Arabic contact IDs...")
        result = client.contact_check(["جهة1", "جهة2"])
        for item in result.results:
            status = "✓ Available" if item.available else "✗ Taken"
            print(f"  {item.id}: {status}")

        client.logout()
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False
    finally:
        client.disconnect()


def test_host_commands():
    """Test host commands."""
    print("\n" + "=" * 60)
    print("HOST COMMANDS")
    print("=" * 60)

    client = create_client()

    try:
        client.connect()
        client.login("testregistrar", "testpassword")

        # Host Check - ASCII
        print("\n[host:check] ASCII hosts...")
        result = client.host_check(["ns1.example.ae", "ns2.example.ae", "taken-ns.example.ae"])
        for item in result.results:
            status = "✓ Available" if item.available else "✗ Taken"
            print(f"  {item.name}: {status}")

        # Host Check - IDN
        print("\n[host:check] IDN hosts (.امارات)...")
        result = client.host_check(["ns1.مثال.امارات", "ns2.مثال.امارات"])
        for item in result.results:
            status = "✓ Available" if item.available else "✗ Taken"
            print(f"  {item.name}: {status}")

        client.logout()
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False
    finally:
        client.disconnect()


def test_poll_commands():
    """Test poll commands."""
    print("\n" + "=" * 60)
    print("POLL COMMANDS")
    print("=" * 60)

    client = create_client()

    try:
        client.connect()
        client.login("testregistrar", "testpassword")

        # Poll Request
        print("\n[poll:req] Requesting poll message...")
        response, message = client.poll_request()
        print(f"  ✓ Code: {response.code} - {response.message}")
        if message:
            print(f"  ✓ Message ID: {message.id}")
            print(f"  ✓ Message: {message.message}")
        else:
            print(f"  ✓ No messages in queue")

        client.logout()
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False
    finally:
        client.disconnect()


def test_cli_commands():
    """Test CLI commands."""
    print("\n" + "=" * 60)
    print("CLI COMMANDS")
    print("=" * 60)

    import subprocess

    base_cmd = [
        "epp",
        "--host", "localhost",
        "--port", "7700",
        "--cert", f"{CERT_DIR}/client.crt",
        "--key", f"{CERT_DIR}/client.key",
        "--ca", f"{CERT_DIR}/ca.crt",
        "-u", "testregistrar",
        "-P", "testpass"
    ]

    tests = [
        ("hello", ["hello"]),
        ("domain check (ASCII)", ["domain", "check", "example.ae", "test.ae"]),
        ("domain check (IDN)", ["domain", "check", "مثال.امارات", "تجربة.امارات"]),
        ("domain check (JSON)", ["--format", "json", "domain", "check", "example.ae"]),
        ("contact check", ["contact", "check", "contact1", "contact2"]),
        ("host check", ["host", "check", "ns1.example.ae", "ns2.example.ae"]),
        ("host check (IDN)", ["host", "check", "ns1.مثال.امارات"]),
    ]

    all_passed = True
    for name, args in tests:
        print(f"\n[CLI] {name}...")
        try:
            result = subprocess.run(
                base_cmd + args,
                capture_output=True,
                text=True,
                timeout=30,
                cwd="/home/alhammadi/Downloads/ARI/epp-client",
                env={**os.environ, "PATH": "/home/alhammadi/Downloads/ARI/epp-client/venv/bin:" + os.environ.get("PATH", "")}
            )
            if result.returncode == 0:
                print(f"  ✓ Success")
                # Show first few lines of output
                lines = result.stdout.strip().split("\n")[:5]
                for line in lines:
                    print(f"    {line}")
            else:
                print(f"  ✗ Failed: {result.stderr}")
                all_passed = False
        except Exception as e:
            print(f"  ✗ Error: {e}")
            all_passed = False

    return all_passed


def main():
    """Run all tests."""
    print("\n" + "#" * 60)
    print("COMPREHENSIVE EPP CLIENT TEST")
    print("Including IDN Support for .امارات")
    print("#" * 60)

    results = []

    results.append(("Session Commands", test_session_commands()))
    results.append(("Domain Commands", test_domain_commands()))
    results.append(("Contact Commands", test_contact_commands()))
    results.append(("Host Commands", test_host_commands()))
    results.append(("Poll Commands", test_poll_commands()))
    results.append(("CLI Commands", test_cli_commands()))

    # Summary
    print("\n" + "#" * 60)
    print("TEST SUMMARY")
    print("#" * 60)

    all_passed = True
    for name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False

    print("\n" + "#" * 60)
    if all_passed:
        print("ALL TESTS PASSED!")
    else:
        print("SOME TESTS FAILED!")
    print("#" * 60 + "\n")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
