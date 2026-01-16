#!/usr/bin/env python3
"""
Domain Operations Example

Demonstrates domain-related EPP operations:
- Check availability
- Create domain
- Query domain info
- Update domain
- Renew domain
- Transfer domain
- Delete domain
"""

import logging
import sys
from datetime import datetime, timedelta

from epp_client import (
    EPPClient,
    EPPConnectionError,
    EPPAuthenticationError,
    EPPObjectNotFound,
    EPPObjectExists,
    EPPCommandError,
)

logging.basicConfig(level=logging.INFO)


def main():
    """Main example function."""

    # Configuration - replace with your actual values
    client = EPPClient(
        host="epp.registry.ae",
        port=700,
        cert_file="/path/to/client.crt",
        key_file="/path/to/client.key",
        ca_file="/path/to/ca.crt",
    )

    client_id = "your_registrar_id"
    password = "your_password"

    # Using context manager for automatic connect/disconnect
    with client:
        print("Connected to EPP server")

        # Login
        client.login(client_id, password)
        print("Logged in successfully")

        # =====================================================================
        # DOMAIN CHECK
        # =====================================================================
        print("\n--- Domain Check ---")

        domains = ["newdomain.ae", "example.ae", "test123.ae"]
        result = client.domain_check(domains)

        available_domains = []
        for item in result.results:
            status = "Available" if item.available else "Taken"
            print(f"  {item.name}: {status}")
            if item.available:
                available_domains.append(item.name)

        # =====================================================================
        # DOMAIN CREATE
        # =====================================================================
        print("\n--- Domain Create ---")

        if available_domains:
            domain_to_create = available_domains[0]
            print(f"  Creating domain: {domain_to_create}")

            try:
                # Prerequisites: contacts must exist
                # Assuming contacts "registrant1", "admin1", "tech1" exist

                result = client.domain_create(
                    name=domain_to_create,
                    registrant="registrant1",
                    admin="admin1",
                    tech="tech1",
                    nameservers=["ns1.example.ae", "ns2.example.ae"],
                    period=1,  # 1 year
                    period_unit="y",
                )

                print(f"  Domain created: {result.name}")
                print(f"  Created: {result.cr_date}")
                print(f"  Expires: {result.ex_date}")

            except EPPObjectExists:
                print(f"  Domain {domain_to_create} already exists")
            except EPPCommandError as e:
                print(f"  Create failed: {e}")
        else:
            print("  No available domains to create")

        # =====================================================================
        # DOMAIN INFO
        # =====================================================================
        print("\n--- Domain Info ---")

        try:
            info = client.domain_info("example.ae")

            print(f"  Name: {info.name}")
            print(f"  ROID: {info.roid}")
            print(f"  Status: {', '.join(info.status)}")
            print(f"  Registrant: {info.registrant}")

            print("  Contacts:")
            for contact in info.contacts:
                print(f"    {contact.type}: {contact.id}")

            print(f"  Nameservers: {', '.join(info.nameservers)}")
            print(f"  Sponsoring Registrar: {info.cl_id}")
            print(f"  Created: {info.cr_date}")
            print(f"  Expires: {info.ex_date}")

        except EPPObjectNotFound:
            print("  Domain not found")

        # =====================================================================
        # DOMAIN UPDATE
        # =====================================================================
        print("\n--- Domain Update ---")

        try:
            # Add/remove nameservers
            client.domain_update(
                name="example.ae",
                add_ns=["ns3.example.ae"],
                rem_ns=["ns2.example.ae"],
            )
            print("  Nameservers updated")

            # Add client lock status
            client.domain_update(
                name="example.ae",
                add_status=["clientTransferProhibited"],
            )
            print("  Transfer lock added")

            # Update registrant
            client.domain_update(
                name="example.ae",
                new_registrant="newregistrant1",
            )
            print("  Registrant updated")

        except EPPObjectNotFound:
            print("  Domain not found")
        except EPPCommandError as e:
            print(f"  Update failed: {e}")

        # =====================================================================
        # DOMAIN RENEW
        # =====================================================================
        print("\n--- Domain Renew ---")

        try:
            # Get current expiry date
            info = client.domain_info("example.ae")
            current_expiry = info.ex_date.strftime("%Y-%m-%d")

            result = client.domain_renew(
                name="example.ae",
                cur_exp_date=current_expiry,
                period=1,  # Renew for 1 year
            )

            print(f"  Domain renewed: {result.name}")
            print(f"  New expiry: {result.ex_date}")

        except EPPObjectNotFound:
            print("  Domain not found")
        except EPPCommandError as e:
            print(f"  Renew failed: {e}")

        # =====================================================================
        # DOMAIN TRANSFER
        # =====================================================================
        print("\n--- Domain Transfer ---")

        # Transfer Request (as gaining registrar)
        try:
            result = client.domain_transfer_request(
                name="transfer-domain.ae",
                auth_info="domain-auth-code",
                period=1,  # Optional renewal on transfer
            )

            print(f"  Transfer requested: {result.name}")
            print(f"  Status: {result.tr_status}")
            print(f"  Request date: {result.re_date}")
            print(f"  Action date: {result.ac_date}")

        except EPPObjectNotFound:
            print("  Domain not found")
        except EPPCommandError as e:
            print(f"  Transfer request failed: {e}")

        # Transfer Query
        try:
            result = client.domain_transfer_query("transfer-domain.ae")
            print(f"  Transfer status: {result.tr_status}")
        except EPPCommandError as e:
            print(f"  Transfer query failed: {e}")

        # Transfer Approve (as losing registrar)
        # try:
        #     client.domain_transfer_approve("transfer-domain.ae")
        #     print("  Transfer approved")
        # except EPPCommandError as e:
        #     print(f"  Transfer approve failed: {e}")

        # Transfer Reject (as losing registrar)
        # try:
        #     client.domain_transfer_reject("transfer-domain.ae")
        #     print("  Transfer rejected")
        # except EPPCommandError as e:
        #     print(f"  Transfer reject failed: {e}")

        # Transfer Cancel (as requesting registrar)
        # try:
        #     client.domain_transfer_cancel("transfer-domain.ae")
        #     print("  Transfer cancelled")
        # except EPPCommandError as e:
        #     print(f"  Transfer cancel failed: {e}")

        # =====================================================================
        # DOMAIN DELETE
        # =====================================================================
        print("\n--- Domain Delete ---")

        try:
            # Remove all status locks first
            client.domain_update(
                name="domain-to-delete.ae",
                rem_status=["clientDeleteProhibited"],
            )

            # Delete the domain
            client.domain_delete("domain-to-delete.ae")
            print("  Domain deleted successfully")

        except EPPObjectNotFound:
            print("  Domain not found")
        except EPPCommandError as e:
            print(f"  Delete failed: {e}")

        # Logout
        client.logout()
        print("\nLogged out successfully")


if __name__ == "__main__":
    main()
