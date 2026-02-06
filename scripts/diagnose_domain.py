#!/usr/bin/env python3
"""
Diagnostic script to check why domains created via EPP don't show in portal.

Run with: python3 scripts/diagnose_domain.py <domain_name>
"""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from database.connection import initialize_pool, get_pool


async def diagnose_domain(domain_name: str):
    """Run diagnostics on a domain."""

    # Initialize database
    await initialize_pool()
    pool = await get_pool()

    print(f"\n{'='*60}")
    print(f"Diagnosing domain: {domain_name}")
    print(f"{'='*60}\n")

    # 1. Check if domain exists in DOMAINS table
    print("1. Checking DOMAINS table...")
    domain = await pool.query_one("""
        SELECT dom_roid, dom_name, dom_zone, dom_registration_id,
               dom_registrant_roid, dom_dns_qualified, dom_dns_hold,
               dom_active_indicator, lng_id
        FROM domains
        WHERE LOWER(dom_name) = LOWER(:name)
    """, {"name": domain_name})

    if not domain:
        print(f"   ERROR: Domain '{domain_name}' NOT FOUND in DOMAINS table!")
        return

    print(f"   Found domain:")
    for key, value in domain.items():
        print(f"      {key}: {value}")

    # Check DOM_ACTIVE_INDICATOR
    active_indicator = domain.get("DOM_ACTIVE_INDICATOR", "")
    if active_indicator != "0":
        print(f"\n   WARNING: DOM_ACTIVE_INDICATOR = '{active_indicator}'")
        print(f"            Should be '0' for active domains!")
        print(f"            This may cause the domain to not show in portal search.")
        print(f"            Fix with: UPDATE DOMAINS SET DOM_ACTIVE_INDICATOR = '0' WHERE DOM_ROID = '{domain['DOM_ROID']}'")

    roid = domain["DOM_ROID"]
    reg_id = domain["DOM_REGISTRATION_ID"]

    # 2. Check REGISTRY_OBJECTS
    print("\n2. Checking REGISTRY_OBJECTS table...")
    obj = await pool.query_one("""
        SELECT obj_roid, obj_type, obj_status, obj_create_date,
               obj_create_user_id, obj_manage_account_id, obj_locked,
               obj_update_date, obj_update_user_id
        FROM registry_objects
        WHERE obj_roid = :roid
    """, {"roid": roid})

    if not obj:
        print(f"   ERROR: Registry object NOT FOUND for ROID {roid}!")
        return

    print(f"   Found registry object:")
    for key, value in obj.items():
        print(f"      {key}: {value}")

    create_user_id = obj["OBJ_CREATE_USER_ID"]
    manage_account_id = obj["OBJ_MANAGE_ACCOUNT_ID"]

    # 3. Check create user exists
    print(f"\n3. Checking USERS table for create user (id={create_user_id})...")
    user = await pool.query_one("""
        SELECT usr_id, usr_username, usr_account_id, usr_type, usr_status
        FROM users
        WHERE usr_id = :user_id
    """, {"user_id": create_user_id})

    if not user:
        print(f"   ERROR: User with ID {create_user_id} NOT FOUND!")
        print("   This is why the domain doesn't show in portal!")
        return

    print(f"   Found user:")
    for key, value in user.items():
        print(f"      {key}: {value}")

    user_account_id = user["USR_ACCOUNT_ID"]

    # 4. Check user's account exists
    print(f"\n4. Checking ACCOUNTS table for user's account (id={user_account_id})...")
    user_account = await pool.query_one("""
        SELECT acc_id, acc_client_id, acc_name, acc_status
        FROM accounts
        WHERE acc_id = :acc_id
    """, {"acc_id": user_account_id})

    if not user_account:
        print(f"   ERROR: Account with ID {user_account_id} NOT FOUND!")
        print("   This is why the domain doesn't show in portal!")
        return

    print(f"   Found account:")
    for key, value in user_account.items():
        print(f"      {key}: {value}")

    # 5. Check sponsoring account
    print(f"\n5. Checking ACCOUNTS table for sponsor (id={manage_account_id})...")
    sponsor = await pool.query_one("""
        SELECT acc_id, acc_client_id, acc_name, acc_status
        FROM accounts
        WHERE acc_id = :acc_id
    """, {"acc_id": manage_account_id})

    if not sponsor:
        print(f"   ERROR: Sponsoring account with ID {manage_account_id} NOT FOUND!")
        return

    print(f"   Found sponsor account:")
    for key, value in sponsor.items():
        print(f"      {key}: {value}")

    # 6. Check domain_registration
    print(f"\n6. Checking DOMAIN_REGISTRATIONS table (id={reg_id})...")
    if reg_id:
        reg = await pool.query_one("""
            SELECT dre_id, dre_roid, dre_seq, dre_period, dre_unit,
                   dre_start_date, dre_expire_date, dre_status
            FROM domain_registrations
            WHERE dre_id = :reg_id
        """, {"reg_id": reg_id})

        if not reg:
            print(f"   ERROR: Registration with ID {reg_id} NOT FOUND!")
        else:
            print(f"   Found registration:")
            for key, value in reg.items():
                print(f"      {key}: {value}")
    else:
        print("   WARNING: No registration ID set (DOM_REGISTRATION_ID is NULL)")

    # 7. Test the domain_search view directly
    print("\n7. Testing domain_search view...")
    search_result = await pool.query_one("""
        SELECT dom_roid, dom_name, obj_status, sponsor, creator,
               obj_create_date, dre_expire_date
        FROM domain_search
        WHERE LOWER(dom_name) = LOWER(:name)
    """, {"name": domain_name})

    if not search_result:
        print(f"   ERROR: Domain NOT FOUND in domain_search view!")
        print("   This confirms the issue - one of the JOINs is failing.")

        # Try to identify which join fails
        print("\n   Debugging JOIN failures...")

        # Test join condition by condition
        test1 = await pool.query_one("""
            SELECT COUNT(*) as cnt FROM users WHERE usr_id = :user_id
        """, {"user_id": create_user_id})
        print(f"   - Users with usr_id={create_user_id}: {test1['CNT']}")

        test2 = await pool.query_one("""
            SELECT COUNT(*) as cnt FROM users u
            JOIN accounts a ON a.acc_id = u.usr_account_id
            WHERE u.usr_id = :user_id
        """, {"user_id": create_user_id})
        print(f"   - Users+Accounts join for usr_id={create_user_id}: {test2['CNT']}")

    else:
        print(f"   SUCCESS! Domain found in domain_search view:")
        for key, value in search_result.items():
            print(f"      {key}: {value}")

    # 8. Check EPP statuses
    print("\n8. Checking EPP_DOMAIN_STATUSES table...")
    statuses = await pool.query_all("""
        SELECT eds_roid, eds_status
        FROM epp_domain_statuses
        WHERE eds_roid = :roid
    """, {"roid": roid})

    if not statuses:
        print("   WARNING: No EPP statuses found for this domain")
    else:
        print(f"   Found {len(statuses)} status(es):")
        for s in statuses:
            print(f"      - {s['EDS_STATUS']}")

    print(f"\n{'='*60}")
    print("Diagnosis complete!")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/diagnose_domain.py <domain_name>")
        print("Example: python3 scripts/diagnose_domain.py example.ae")
        sys.exit(1)

    domain_name = sys.argv[1]
    asyncio.run(diagnose_domain(domain_name))
