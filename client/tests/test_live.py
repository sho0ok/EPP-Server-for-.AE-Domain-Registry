#!/usr/bin/env python3
"""
Live Client Test

Tests the EPP client against the mock server.
"""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from epp_client import EPPClient, AsyncEPPClient

# Test certificates
CERT_DIR = "/home/alhammadi/Downloads/ARI/test-certs"


def test_sync_client():
    """Test synchronous client."""
    print("\n" + "=" * 60)
    print("Testing Synchronous EPP Client")
    print("=" * 60)

    client = EPPClient(
        host="localhost",
        port=7700,
        cert_file=f"{CERT_DIR}/client.crt",
        key_file=f"{CERT_DIR}/client.key",
        ca_file=f"{CERT_DIR}/ca.crt",
        timeout=30,
        verify_server=True,
    )

    try:
        # Connect
        print("\n1. Connecting to server...")
        greeting = client.connect()
        print(f"   Server ID: {greeting.server_id}")
        print(f"   Server Date: {greeting.server_date}")
        print(f"   Versions: {greeting.version}")
        print(f"   Languages: {greeting.lang}")
        print(f"   Objects: {greeting.obj_uris}")

        # Login
        print("\n2. Logging in...")
        response = client.login("testregistrar", "testpassword")
        print(f"   Response: {response.code} - {response.message}")

        # Domain check
        print("\n3. Checking domain availability...")
        domains = ["example.test", "available.test", "taken-domain.test"]
        result = client.domain_check(domains)
        for item in result.results:
            status = "Available" if item.available else "Taken"
            print(f"   {item.name}: {status}")

        # Contact check
        print("\n4. Checking contact availability...")
        contacts = ["contact1", "taken-contact", "newcontact"]
        result = client.contact_check(contacts)
        for item in result.results:
            status = "Available" if item.available else "Taken"
            print(f"   {item.id}: {status}")

        # Host check
        print("\n5. Checking host availability...")
        hosts = ["ns1.example.test", "taken-ns.example.test", "ns3.new.test"]
        result = client.host_check(hosts)
        for item in result.results:
            status = "Available" if item.available else "Taken"
            print(f"   {item.name}: {status}")

        # Logout
        print("\n6. Logging out...")
        response = client.logout()
        print(f"   Response: {response.code} - {response.message}")

        print("\n" + "=" * 60)
        print("Synchronous Client Test: PASSED")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        client.disconnect()


async def test_async_client():
    """Test asynchronous client."""
    print("\n" + "=" * 60)
    print("Testing Asynchronous EPP Client")
    print("=" * 60)

    client = AsyncEPPClient(
        host="localhost",
        port=7700,
        cert_file=f"{CERT_DIR}/client.crt",
        key_file=f"{CERT_DIR}/client.key",
        ca_file=f"{CERT_DIR}/ca.crt",
        timeout=30,
    )

    try:
        # Connect
        print("\n1. Connecting to server...")
        greeting = await client.connect()
        print(f"   Server ID: {greeting.server_id}")

        # Login
        print("\n2. Logging in...")
        response = await client.login("testregistrar", "testpassword")
        print(f"   Response: {response.code} - {response.message}")

        # Multiple domain checks
        print("\n3. Running multiple domain checks...")
        domains_to_check = [
            ["batch1-a.test", "batch1-b.test"],
            ["batch2-a.test", "batch2-b.test"],
            ["batch3-a.test", "batch3-b.test"],
        ]

        for batch in domains_to_check:
            result = await client.domain_check(batch)
            print(f"   Batch: {[item.name for item in result.results]}")

        # Logout
        print("\n4. Logging out...")
        response = await client.logout()
        print(f"   Response: {response.code} - {response.message}")

        print("\n" + "=" * 60)
        print("Asynchronous Client Test: PASSED")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        await client.disconnect()


async def test_context_manager():
    """Test async context manager."""
    print("\n" + "=" * 60)
    print("Testing Async Context Manager")
    print("=" * 60)

    try:
        async with AsyncEPPClient(
            host="localhost",
            port=7700,
            cert_file=f"{CERT_DIR}/client.crt",
            key_file=f"{CERT_DIR}/client.key",
            ca_file=f"{CERT_DIR}/ca.crt",
        ) as client:
            print("\n1. Connected via context manager")
            print(f"   Server: {client.greeting.server_id}")

            await client.login("testregistrar", "testpassword")
            print("2. Logged in")

            result = await client.domain_check(["context-test.test"])
            print(f"3. Checked domain: {result.results[0].name}")

            await client.logout()
            print("4. Logged out")

        print("\n" + "=" * 60)
        print("Context Manager Test: PASSED")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("\n" + "#" * 60)
    print("EPP Client Live Tests")
    print("#" * 60)
    print(f"\nUsing certificates from: {CERT_DIR}")
    print("Connecting to: localhost:7700")

    results = []

    # Test sync client
    results.append(("Sync Client", test_sync_client()))

    # Test async client
    results.append(("Async Client", asyncio.run(test_async_client())))

    # Test context manager
    results.append(("Context Manager", asyncio.run(test_context_manager())))

    # Summary
    print("\n" + "#" * 60)
    print("Test Summary")
    print("#" * 60)
    all_passed = True
    for name, passed in results:
        status = "PASSED" if passed else "FAILED"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False

    print("\n" + "#" * 60)
    if all_passed:
        print("All tests PASSED!")
    else:
        print("Some tests FAILED!")
    print("#" * 60 + "\n")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
