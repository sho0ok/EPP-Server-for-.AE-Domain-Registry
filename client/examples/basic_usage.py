#!/usr/bin/env python3
"""
Basic EPP Client Usage Example

Demonstrates the fundamental operations with the EPP client.
"""

import logging
import sys

from epp_client import EPPClient, EPPConnectionError, EPPAuthenticationError

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


def main():
    """Main example function."""

    # Configuration - replace with your actual values
    config = {
        "host": "epp.registry.ae",
        "port": 700,
        "cert_file": "/path/to/client.crt",
        "key_file": "/path/to/client.key",
        "ca_file": "/path/to/ca.crt",
        "timeout": 30,
    }

    # Credentials - replace with your actual values
    client_id = "your_registrar_id"
    password = "your_password"

    print("=" * 60)
    print("EPP Client Basic Usage Example")
    print("=" * 60)

    # Create client instance
    client = EPPClient(**config)

    try:
        # Connect to server
        print("\n1. Connecting to EPP server...")
        greeting = client.connect()
        print(f"   Connected to: {greeting.server_id}")
        print(f"   Server date: {greeting.server_date}")
        print(f"   Supported versions: {greeting.version}")

        # Login
        print("\n2. Logging in...")
        response = client.login(client_id, password)
        print(f"   Login successful! Response code: {response.code}")

        # Check domain availability
        print("\n3. Checking domain availability...")
        domains_to_check = ["example.ae", "test.ae", "available-domain.ae"]
        result = client.domain_check(domains_to_check)

        for item in result.results:
            status = "AVAILABLE" if item.available else "TAKEN"
            reason = f" ({item.reason})" if item.reason else ""
            print(f"   {item.name}: {status}{reason}")

        # Get domain info (for an existing domain)
        print("\n4. Getting domain info...")
        try:
            domain_info = client.domain_info("example.ae")
            print(f"   Domain: {domain_info.name}")
            print(f"   ROID: {domain_info.roid}")
            print(f"   Status: {', '.join(domain_info.status)}")
            print(f"   Registrant: {domain_info.registrant}")
            print(f"   Expiry: {domain_info.ex_date}")
            print(f"   Nameservers: {', '.join(domain_info.nameservers)}")
        except Exception as e:
            print(f"   Domain not found or error: {e}")

        # Check contact availability
        print("\n5. Checking contact availability...")
        contact_result = client.contact_check(["contact123", "newcontact"])
        for item in contact_result.results:
            status = "AVAILABLE" if item.available else "EXISTS"
            print(f"   {item.id}: {status}")

        # Check host availability
        print("\n6. Checking host availability...")
        host_result = client.host_check(["ns1.example.ae", "ns2.example.ae"])
        for item in host_result.results:
            status = "AVAILABLE" if item.available else "EXISTS"
            print(f"   {item.name}: {status}")

        # Poll for messages
        print("\n7. Checking poll queue...")
        poll_msg = client.poll_request()
        if poll_msg:
            print(f"   Message ID: {poll_msg.id}")
            print(f"   Count: {poll_msg.count}")
            print(f"   Message: {poll_msg.message}")
            # Acknowledge the message
            # client.poll_ack(poll_msg.id)
        else:
            print("   No messages in queue")

        # Logout
        print("\n8. Logging out...")
        client.logout()
        print("   Logged out successfully")

    except EPPConnectionError as e:
        print(f"\nConnection error: {e}")
        sys.exit(1)
    except EPPAuthenticationError as e:
        print(f"\nAuthentication error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)
    finally:
        # Disconnect
        client.disconnect()
        print("\nDisconnected from server")

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
