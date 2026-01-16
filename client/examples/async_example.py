#!/usr/bin/env python3
"""
Async EPP Client Example

Demonstrates asynchronous EPP operations for high-performance scenarios.
"""

import asyncio
import logging
import sys

from epp_client import AsyncEPPClient, EPPConnectionPool, PoolConfig, create_pool

logging.basicConfig(level=logging.INFO)


async def basic_async_example():
    """Basic async client usage."""
    print("\n--- Basic Async Client ---")

    client = AsyncEPPClient(
        host="epp.registry.ae",
        port=700,
        cert_file="/path/to/client.crt",
        key_file="/path/to/client.key",
        ca_file="/path/to/ca.crt",
    )

    # Using async context manager
    async with client:
        await client.login("registrar1", "password123")
        print("  Logged in")

        # Check domains asynchronously
        result = await client.domain_check(["example.ae", "test.ae"])
        for item in result.results:
            status = "available" if item.available else "taken"
            print(f"  {item.name}: {status}")

        await client.logout()
        print("  Logged out")


async def concurrent_checks():
    """Run multiple checks concurrently."""
    print("\n--- Concurrent Domain Checks ---")

    client = AsyncEPPClient(
        host="epp.registry.ae",
        port=700,
        cert_file="/path/to/client.crt",
        key_file="/path/to/client.key",
        ca_file="/path/to/ca.crt",
    )

    await client.connect()
    await client.login("registrar1", "password123")

    # Create multiple check tasks
    domains_batches = [
        ["domain1.ae", "domain2.ae", "domain3.ae"],
        ["domain4.ae", "domain5.ae", "domain6.ae"],
        ["domain7.ae", "domain8.ae", "domain9.ae"],
    ]

    # Note: EPP protocol is synchronous per connection
    # For true concurrency, use connection pool
    # This example shows sequential async operations
    for batch in domains_batches:
        result = await client.domain_check(batch)
        print(f"  Checked batch: {[item.name for item in result.results]}")

    await client.logout()
    await client.disconnect()


async def connection_pool_example():
    """Using connection pool for high throughput."""
    print("\n--- Connection Pool Example ---")

    # Create pool configuration
    config = PoolConfig(
        host="epp.registry.ae",
        port=700,
        cert_file="/path/to/client.crt",
        key_file="/path/to/client.key",
        ca_file="/path/to/ca.crt",
        client_id="registrar1",
        password="password123",
        min_connections=2,
        max_connections=5,
        idle_timeout=300.0,  # 5 minutes
    )

    # Create and start pool
    pool = EPPConnectionPool(config)
    await pool.start()

    print(f"  Pool started: {pool.stats()}")

    try:
        # Use pool to execute operations
        async with pool.acquire() as client:
            result = await client.domain_check(["example.ae"])
            print(f"  Check result: {result.results[0].name} - {'available' if result.results[0].available else 'taken'}")

        # Execute multiple operations concurrently
        async def check_domain(domain):
            async with pool.acquire() as client:
                result = await client.domain_check([domain])
                return result.results[0]

        # Run concurrent checks using the pool
        domains = ["test1.ae", "test2.ae", "test3.ae", "test4.ae", "test5.ae"]
        tasks = [check_domain(d) for d in domains]
        results = await asyncio.gather(*tasks)

        for item in results:
            status = "available" if item.available else "taken"
            print(f"  {item.name}: {status}")

        print(f"  Pool stats after operations: {pool.stats()}")

    finally:
        # Stop pool
        await pool.stop()
        print("  Pool stopped")


async def pool_convenience_function():
    """Using the convenience function to create a pool."""
    print("\n--- Pool Convenience Function ---")

    # Quick pool creation
    pool = await create_pool(
        host="epp.registry.ae",
        client_id="registrar1",
        password="password123",
        cert_file="/path/to/client.crt",
        key_file="/path/to/client.key",
        min_connections=2,
        max_connections=10,
    )

    try:
        # Using execute() helper
        result = await pool.execute(
            lambda client: client.domain_check(["example.ae"])
        )
        print(f"  Result: {result.results[0].name}")

        # Get host info
        info = await pool.execute(
            lambda client: client.host_info("ns1.example.ae")
        )
        print(f"  Host: {info.name}")
        print(f"  Addresses: {[a.address for a in info.addresses]}")

    finally:
        await pool.stop()


async def bulk_domain_registration():
    """Example: Bulk domain registration using pool."""
    print("\n--- Bulk Domain Registration ---")

    pool = await create_pool(
        host="epp.registry.ae",
        client_id="registrar1",
        password="password123",
        cert_file="/path/to/client.crt",
        key_file="/path/to/client.key",
        min_connections=3,
        max_connections=10,
    )

    domains_to_register = [
        {"name": "domain1.ae", "registrant": "contact1"},
        {"name": "domain2.ae", "registrant": "contact2"},
        {"name": "domain3.ae", "registrant": "contact3"},
    ]

    async def register_domain(domain_info):
        async with pool.acquire() as client:
            try:
                # Check availability first
                check = await client.domain_check([domain_info["name"]])
                if not check.results[0].available:
                    return {"name": domain_info["name"], "status": "already_exists"}

                # Create domain
                result = await client.domain_create(
                    name=domain_info["name"],
                    registrant=domain_info["registrant"],
                    admin=domain_info.get("admin", domain_info["registrant"]),
                    tech=domain_info.get("tech", domain_info["registrant"]),
                )
                return {"name": result.name, "status": "created", "expires": result.ex_date}

            except Exception as e:
                return {"name": domain_info["name"], "status": "error", "error": str(e)}

    # Register all domains concurrently
    tasks = [register_domain(d) for d in domains_to_register]
    results = await asyncio.gather(*tasks)

    for result in results:
        print(f"  {result['name']}: {result['status']}")

    await pool.stop()


async def main():
    """Run all examples."""
    print("=" * 60)
    print("Async EPP Client Examples")
    print("=" * 60)

    # Note: These examples require a real EPP server connection
    # Uncomment the examples you want to run

    try:
        # await basic_async_example()
        # await concurrent_checks()
        # await connection_pool_example()
        # await pool_convenience_function()
        # await bulk_domain_registration()

        print("\nExamples are commented out - configure and uncomment to run")
        print("Make sure to update the server credentials and certificate paths")

    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("Examples completed")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
