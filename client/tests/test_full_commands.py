#!/usr/bin/env python3
"""
Full EPP Command Test

Tests ALL EPP commands including create, update, delete, renew, transfer.
Including IDN support for .امارات
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


def test_domain_lifecycle():
    """Test full domain lifecycle: create, info, update, renew, delete."""
    print("\n" + "=" * 60)
    print("DOMAIN LIFECYCLE (ASCII & IDN)")
    print("=" * 60)

    client = create_client()

    try:
        client.connect()
        client.login("testregistrar", "testpassword")

        # =====================================================
        # ASCII Domain
        # =====================================================
        print("\n--- ASCII Domain: newdomain.ae ---")

        # Create
        print("\n[domain:create] Creating newdomain.ae...")
        result = client.domain_create(
            name="newdomain.ae",
            registrant="REG001",
            admin="ADM001",
            tech="TCH001",
            nameservers=["ns1.example.ae", "ns2.example.ae"],
            period=1,
        )
        print(f"  ✓ Created: {result.name}")
        print(f"  ✓ Created Date: {result.cr_date}")
        print(f"  ✓ Expiry Date: {result.ex_date}")

        # Info
        print("\n[domain:info] Getting domain info...")
        info = client.domain_info("newdomain.ae")
        print(f"  ✓ Name: {info.name}")
        print(f"  ✓ ROID: {info.roid}")
        print(f"  ✓ Status: {info.status}")
        print(f"  ✓ Registrant: {info.registrant}")

        # Update
        print("\n[domain:update] Updating domain...")
        response = client.domain_update(
            name="newdomain.ae",
            add_ns=["ns3.example.ae"],
        )
        print(f"  ✓ Update Response: {response.code} - {response.message}")

        # Renew
        print("\n[domain:renew] Renewing domain...")
        renew_result = client.domain_renew(
            name="newdomain.ae",
            cur_exp_date="2025-01-01",
            period=1,
        )
        print(f"  ✓ Renewed: {renew_result.name}")
        print(f"  ✓ New Expiry: {renew_result.ex_date}")

        # Delete
        print("\n[domain:delete] Deleting domain...")
        response = client.domain_delete("newdomain.ae")
        print(f"  ✓ Delete Response: {response.code} - {response.message}")

        # =====================================================
        # IDN Domain (.امارات)
        # =====================================================
        print("\n--- IDN Domain: نطاق.امارات ---")

        # Create IDN
        print("\n[domain:create] Creating نطاق.امارات...")
        result = client.domain_create(
            name="نطاق.امارات",
            registrant="REG001",
            admin="ADM001",
            tech="TCH001",
            nameservers=["ns1.مثال.امارات", "ns2.مثال.امارات"],
            period=1,
        )
        print(f"  ✓ Created: {result.name}")
        print(f"  ✓ Expiry Date: {result.ex_date}")

        # Info IDN
        print("\n[domain:info] Getting IDN domain info...")
        info = client.domain_info("نطاق.امارات")
        print(f"  ✓ Name: {info.name}")

        # Renew IDN
        print("\n[domain:renew] Renewing IDN domain...")
        renew_result = client.domain_renew(
            name="نطاق.امارات",
            cur_exp_date="2025-01-01",
            period=2,
        )
        print(f"  ✓ Renewed: {renew_result.name}")
        print(f"  ✓ New Expiry: {renew_result.ex_date}")

        # Delete IDN
        print("\n[domain:delete] Deleting IDN domain...")
        response = client.domain_delete("نطاق.امارات")
        print(f"  ✓ Delete Response: {response.code}")

        client.logout()
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.disconnect()


def test_domain_transfer():
    """Test domain transfer operations."""
    print("\n" + "=" * 60)
    print("DOMAIN TRANSFER")
    print("=" * 60)

    client = create_client()

    try:
        client.connect()
        client.login("testregistrar", "testpassword")

        # Transfer Request
        print("\n[domain:transfer request] Requesting transfer...")
        result = client.domain_transfer_request(
            name="transfer-test.ae",
            auth_info="auth123",
        )
        print(f"  ✓ Domain: {result.name}")
        print(f"  ✓ Status: {result.tr_status}")
        print(f"  ✓ Requesting Registrar: {result.re_id}")
        print(f"  ✓ Request Date: {result.re_date}")

        # Transfer Query
        print("\n[domain:transfer query] Querying transfer...")
        result = client.domain_transfer_query("transfer-test.ae")
        print(f"  ✓ Domain: {result.name}")
        print(f"  ✓ Status: {result.tr_status}")

        # Transfer Approve
        print("\n[domain:transfer approve] Approving transfer...")
        response = client.domain_transfer_approve("transfer-test.ae")
        print(f"  ✓ Response: {response.code} - {response.message}")

        # Transfer Reject (on different domain)
        print("\n[domain:transfer reject] Rejecting transfer...")
        response = client.domain_transfer_reject("reject-test.ae")
        print(f"  ✓ Response: {response.code} - {response.message}")

        # Transfer Cancel
        print("\n[domain:transfer cancel] Cancelling transfer...")
        response = client.domain_transfer_cancel("cancel-test.ae")
        print(f"  ✓ Response: {response.code} - {response.message}")

        # IDN Transfer
        print("\n[domain:transfer request] IDN Transfer نقل.امارات...")
        result = client.domain_transfer_request(
            name="نقل.امارات",
            auth_info="auth123",
        )
        print(f"  ✓ IDN Domain: {result.name}")
        print(f"  ✓ Status: {result.tr_status}")

        client.logout()
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.disconnect()


def test_contact_lifecycle():
    """Test full contact lifecycle: create, info, update, delete."""
    print("\n" + "=" * 60)
    print("CONTACT LIFECYCLE")
    print("=" * 60)

    client = create_client()

    try:
        client.connect()
        client.login("testregistrar", "testpassword")

        # Create Contact
        print("\n[contact:create] Creating contact...")
        result = client.contact_create(
            id="NEWCONTACT001",
            name="Test User",
            email="test@example.ae",
            city="Dubai",
            country_code="AE",
            org="Test Organization",
            street=["123 Test Street", "Suite 100"],
            state="Dubai",
            postal_code="00000",
            voice="+971.41234567",
        )
        print(f"  ✓ Created: {result.id}")
        print(f"  ✓ Created Date: {result.cr_date}")

        # Info
        print("\n[contact:info] Getting contact info...")
        info = client.contact_info("NEWCONTACT001")
        print(f"  ✓ ID: {info.id}")
        print(f"  ✓ ROID: {info.roid}")
        print(f"  ✓ Email: {info.email}")
        print(f"  ✓ Voice: {info.voice}")

        # Update
        print("\n[contact:update] Updating contact...")
        response = client.contact_update(
            id="NEWCONTACT001",
            new_email="updated@example.ae",
        )
        print(f"  ✓ Update Response: {response.code} - {response.message}")

        # Delete
        print("\n[contact:delete] Deleting contact...")
        response = client.contact_delete("NEWCONTACT001")
        print(f"  ✓ Delete Response: {response.code} - {response.message}")

        # Arabic Contact ID
        print("\n[contact:create] Creating Arabic contact جهة001...")
        result = client.contact_create(
            id="جهة001",
            name="مستخدم اختبار",
            email="arabic@example.ae",
            city="دبي",
            country_code="AE",
            voice="+971.41234567",
        )
        print(f"  ✓ Created: {result.id}")

        client.logout()
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.disconnect()


def test_host_lifecycle():
    """Test full host lifecycle: create, info, update, delete."""
    print("\n" + "=" * 60)
    print("HOST LIFECYCLE"  )
    print("=" * 60)

    client = create_client()

    try:
        client.connect()
        client.login("testregistrar", "testpassword")

        # Create Host
        print("\n[host:create] Creating ns1.newdomain.ae...")
        result = client.host_create(
            name="ns1.newdomain.ae",
            ipv4=["192.0.2.1"],
            ipv6=["2001:db8::1"],
        )
        print(f"  ✓ Created: {result.name}")
        print(f"  ✓ Created Date: {result.cr_date}")

        # Info
        print("\n[host:info] Getting host info...")
        info = client.host_info("ns1.newdomain.ae")
        print(f"  ✓ Name: {info.name}")
        print(f"  ✓ ROID: {info.roid}")
        print(f"  ✓ Status: {info.status}")
        print(f"  ✓ Addresses: {[(a.address, a.ip_version) for a in info.addresses]}")

        # Update
        print("\n[host:update] Updating host...")
        response = client.host_update(
            name="ns1.newdomain.ae",
            add_ipv4=["192.0.2.2"],
        )
        print(f"  ✓ Update Response: {response.code} - {response.message}")

        # Delete
        print("\n[host:delete] Deleting host...")
        response = client.host_delete("ns1.newdomain.ae")
        print(f"  ✓ Delete Response: {response.code} - {response.message}")

        # IDN Host
        print("\n[host:create] Creating IDN host ns1.نطاق.امارات...")
        result = client.host_create(
            name="ns1.نطاق.امارات",
            ipv4=["192.0.2.10"],
        )
        print(f"  ✓ Created: {result.name}")

        client.logout()
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.disconnect()


def test_cli_create_commands():
    """Test CLI create/update/delete commands."""
    print("\n" + "=" * 60)
    print("CLI CREATE/UPDATE/DELETE COMMANDS")
    print("=" * 60)

    import subprocess

    base_cmd = [
        "/home/alhammadi/Downloads/ARI/epp-client/venv/bin/epp",
        "--host", "localhost",
        "--port", "7700",
        "--cert", f"{CERT_DIR}/client.crt",
        "--key", f"{CERT_DIR}/client.key",
        "--ca", f"{CERT_DIR}/ca.crt",
        "-u", "testregistrar",
        "-P", "testpass"
    ]

    tests = [
        ("domain create", ["domain", "create", "clitest.ae", "--registrant", "REG001", "--admin", "ADM001", "--tech", "TCH001"]),
        ("domain info", ["domain", "info", "clitest.ae"]),
        ("domain renew", ["domain", "renew", "clitest.ae", "--exp-date", "2025-01-01"]),
        ("domain delete", ["domain", "delete", "clitest.ae", "-y"]),
        ("domain create IDN", ["domain", "create", "اختبار.امارات", "--registrant", "REG001"]),
        ("contact create", ["contact", "create", "CLICONTACT", "--name", "Test", "--city", "Dubai", "--country", "AE", "--email", "test@test.ae"]),
        ("contact info", ["contact", "info", "CLICONTACT"]),
        ("contact delete", ["contact", "delete", "CLICONTACT", "-y"]),
        ("host create", ["host", "create", "ns1.clitest.ae", "--ipv4", "192.0.2.1"]),
        ("host info", ["host", "info", "ns1.clitest.ae"]),
        ("host delete", ["host", "delete", "ns1.clitest.ae", "-y"]),
        ("domain transfer request", ["domain", "transfer", "transfer.ae", "request", "--auth-info", "auth123"]),
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
            )
            if result.returncode == 0:
                print(f"  ✓ Success")
                # Show first few lines of output
                lines = result.stdout.strip().split("\n")[:3]
                for line in lines:
                    print(f"    {line}")
            else:
                print(f"  ✗ Failed (code {result.returncode})")
                print(f"    {result.stderr[:200]}")
                all_passed = False
        except Exception as e:
            print(f"  ✗ Error: {e}")
            all_passed = False

    return all_passed


def main():
    """Run all tests."""
    print("\n" + "#" * 60)
    print("FULL EPP COMMAND TEST")
    print("Create, Update, Delete, Renew, Transfer")
    print("ASCII and IDN (.امارات) Support")
    print("#" * 60)

    results = []

    results.append(("Domain Lifecycle", test_domain_lifecycle()))
    results.append(("Domain Transfer", test_domain_transfer()))
    results.append(("Contact Lifecycle", test_contact_lifecycle()))
    results.append(("Host Lifecycle", test_host_lifecycle()))
    results.append(("CLI Commands", test_cli_create_commands()))

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
