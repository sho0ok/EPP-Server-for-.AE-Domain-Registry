"""
EPP Connection Pool

Manages a pool of EPP connections for high-throughput operations.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Callable, List, Optional

from epp_client.async_client import AsyncEPPClient
from epp_client.exceptions import EPPConnectionError

logger = logging.getLogger("epp.pool")


@dataclass
class PoolConfig:
    """Connection pool configuration."""
    host: str
    port: int = 700
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None
    timeout: float = 30.0
    verify_server: bool = True
    client_id: str = ""
    password: str = ""

    # Pool settings
    min_connections: int = 2
    max_connections: int = 10
    idle_timeout: float = 300.0  # 5 minutes
    health_check_interval: float = 60.0  # 1 minute


@dataclass
class PooledConnection:
    """Wrapper for a pooled connection."""
    client: AsyncEPPClient
    created_at: float
    last_used_at: float
    in_use: bool = False

    def is_stale(self, idle_timeout: float) -> bool:
        """Check if connection is stale."""
        return time.time() - self.last_used_at > idle_timeout


class EPPConnectionPool:
    """
    Async connection pool for EPP clients.

    Manages multiple connections for high-throughput operations.
    Automatically handles connection lifecycle, health checks,
    and cleanup of idle connections.

    Example:
        config = PoolConfig(
            host="epp.registry.ae",
            port=700,
            cert_file="client.crt",
            key_file="client.key",
            client_id="registrar1",
            password="password123",
            min_connections=2,
            max_connections=10,
        )

        pool = EPPConnectionPool(config)
        await pool.start()

        # Get a connection from the pool
        async with pool.acquire() as client:
            result = await client.domain_check(["example.ae"])

        await pool.stop()
    """

    def __init__(self, config: PoolConfig):
        """
        Initialize connection pool.

        Args:
            config: Pool configuration
        """
        self.config = config
        self._connections: List[PooledConnection] = []
        self._lock = asyncio.Lock()
        self._started = False
        self._health_check_task: Optional[asyncio.Task] = None
        self._semaphore: Optional[asyncio.Semaphore] = None

    @property
    def size(self) -> int:
        """Current pool size."""
        return len(self._connections)

    @property
    def available(self) -> int:
        """Number of available connections."""
        return sum(1 for c in self._connections if not c.in_use)

    @property
    def in_use(self) -> int:
        """Number of connections in use."""
        return sum(1 for c in self._connections if c.in_use)

    async def start(self) -> None:
        """
        Start the connection pool.

        Creates minimum number of connections and starts health check task.
        """
        if self._started:
            return

        logger.info(f"Starting EPP connection pool (min={self.config.min_connections}, max={self.config.max_connections})")

        self._semaphore = asyncio.Semaphore(self.config.max_connections)

        # Create minimum connections
        for _ in range(self.config.min_connections):
            try:
                conn = await self._create_connection()
                self._connections.append(conn)
            except Exception as e:
                logger.error(f"Failed to create initial connection: {e}")

        if not self._connections:
            raise EPPConnectionError("Failed to create any pool connections")

        # Start health check task
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        self._started = True

        logger.info(f"Connection pool started with {len(self._connections)} connections")

    async def stop(self) -> None:
        """
        Stop the connection pool.

        Closes all connections and stops health check task.
        """
        if not self._started:
            return

        logger.info("Stopping EPP connection pool")

        # Cancel health check
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass

        # Close all connections
        async with self._lock:
            for conn in self._connections:
                try:
                    await conn.client.disconnect()
                except Exception as e:
                    logger.warning(f"Error disconnecting: {e}")

            self._connections.clear()

        self._started = False
        logger.info("Connection pool stopped")

    async def _create_connection(self) -> PooledConnection:
        """Create a new pooled connection."""
        client = AsyncEPPClient(
            host=self.config.host,
            port=self.config.port,
            cert_file=self.config.cert_file,
            key_file=self.config.key_file,
            ca_file=self.config.ca_file,
            timeout=self.config.timeout,
            verify_server=self.config.verify_server,
        )

        await client.connect()
        await client.login(self.config.client_id, self.config.password)

        now = time.time()
        return PooledConnection(
            client=client,
            created_at=now,
            last_used_at=now,
            in_use=False,
        )

    async def _get_connection(self) -> PooledConnection:
        """
        Get an available connection from the pool.

        Creates a new connection if none available and pool not at max.
        """
        async with self._lock:
            # Try to find an available connection
            for conn in self._connections:
                if not conn.in_use and conn.client.is_connected:
                    conn.in_use = True
                    conn.last_used_at = time.time()
                    return conn

            # Create new connection if under max
            if len(self._connections) < self.config.max_connections:
                try:
                    conn = await self._create_connection()
                    conn.in_use = True
                    self._connections.append(conn)
                    return conn
                except Exception as e:
                    logger.error(f"Failed to create new connection: {e}")
                    raise

            # No connections available
            raise EPPConnectionError("No available connections in pool")

    async def _release_connection(self, conn: PooledConnection) -> None:
        """Release a connection back to the pool."""
        async with self._lock:
            conn.in_use = False
            conn.last_used_at = time.time()

    async def acquire(self) -> "PooledConnectionContext":
        """
        Acquire a connection from the pool.

        Returns a context manager that automatically releases
        the connection when done.

        Example:
            async with pool.acquire() as client:
                result = await client.domain_check(["example.ae"])
        """
        if not self._started:
            raise EPPConnectionError("Pool not started")

        await self._semaphore.acquire()

        try:
            conn = await self._get_connection()
            return PooledConnectionContext(self, conn)
        except Exception:
            self._semaphore.release()
            raise

    async def execute(self, func: Callable) -> any:
        """
        Execute a function with a pooled connection.

        Args:
            func: Async function that takes an AsyncEPPClient

        Returns:
            Result of the function

        Example:
            result = await pool.execute(
                lambda client: client.domain_check(["example.ae"])
            )
        """
        async with self.acquire() as client:
            return await func(client)

    async def _health_check_loop(self) -> None:
        """Background task to check connection health."""
        while True:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self._perform_health_check()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")

    async def _perform_health_check(self) -> None:
        """Perform health check on all connections."""
        async with self._lock:
            to_remove = []
            to_create = 0

            for conn in self._connections:
                # Skip in-use connections
                if conn.in_use:
                    continue

                # Check if connection is stale
                if conn.is_stale(self.config.idle_timeout):
                    # Keep minimum connections
                    if len(self._connections) - len(to_remove) > self.config.min_connections:
                        to_remove.append(conn)
                        continue

                # Check if connection is healthy
                if not conn.client.is_connected:
                    to_remove.append(conn)
                    to_create += 1

            # Remove unhealthy connections
            for conn in to_remove:
                try:
                    await conn.client.disconnect()
                except Exception:
                    pass
                self._connections.remove(conn)

            # Create replacement connections
            for _ in range(to_create):
                try:
                    new_conn = await self._create_connection()
                    self._connections.append(new_conn)
                except Exception as e:
                    logger.warning(f"Failed to create replacement connection: {e}")

            if to_remove:
                logger.info(f"Health check: removed {len(to_remove)}, pool size: {len(self._connections)}")

    def stats(self) -> dict:
        """Get pool statistics."""
        return {
            "size": self.size,
            "available": self.available,
            "in_use": self.in_use,
            "min_connections": self.config.min_connections,
            "max_connections": self.config.max_connections,
        }


class PooledConnectionContext:
    """Context manager for pooled connections."""

    def __init__(self, pool: EPPConnectionPool, conn: PooledConnection):
        self._pool = pool
        self._conn = conn

    async def __aenter__(self) -> AsyncEPPClient:
        return self._conn.client

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._pool._release_connection(self._conn)
        self._pool._semaphore.release()
        return False


# Convenience function to create a pool
async def create_pool(
    host: str,
    client_id: str,
    password: str,
    port: int = 700,
    cert_file: str = None,
    key_file: str = None,
    ca_file: str = None,
    min_connections: int = 2,
    max_connections: int = 10,
    **kwargs,
) -> EPPConnectionPool:
    """
    Create and start a connection pool.

    Args:
        host: EPP server hostname
        client_id: Client/registrar ID
        password: Password
        port: EPP server port
        cert_file: Path to client certificate
        key_file: Path to client private key
        ca_file: Path to CA certificate
        min_connections: Minimum pool size
        max_connections: Maximum pool size
        **kwargs: Additional PoolConfig options

    Returns:
        Started EPPConnectionPool

    Example:
        pool = await create_pool(
            host="epp.registry.ae",
            client_id="registrar1",
            password="password123",
            cert_file="client.crt",
            key_file="client.key",
        )
    """
    config = PoolConfig(
        host=host,
        port=port,
        cert_file=cert_file,
        key_file=key_file,
        ca_file=ca_file,
        client_id=client_id,
        password=password,
        min_connections=min_connections,
        max_connections=max_connections,
        **kwargs,
    )

    pool = EPPConnectionPool(config)
    await pool.start()

    return pool
