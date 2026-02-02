"""
Oracle Database Connection Pool

Manages Oracle database connections using oracledb connection pooling.
All EPP operations use this pool for database access.
"""

import os
import logging
from typing import Any, Dict, List, Optional, Tuple
from contextlib import asynccontextmanager
import oracledb

logger = logging.getLogger("epp.database")


class DatabaseError(Exception):
    """Base exception for database errors"""
    pass


class ConnectionError(DatabaseError):
    """Error establishing database connection"""
    pass


class QueryError(DatabaseError):
    """Error executing database query"""
    pass


class TransactionConnection:
    """
    Wrapper for connection with transaction-friendly execute method.

    Used within pool.transaction() context manager.
    """

    def __init__(self, conn):
        self._conn = conn

    async def execute(self, sql: str, params: Optional[Dict[str, Any]] = None) -> int:
        """
        Execute SQL statement within the transaction.

        Args:
            sql: SQL statement with named parameters
            params: Dictionary of parameter values

        Returns:
            Number of rows affected
        """
        cursor = self._conn.cursor()
        cursor.execute(sql, params or {})
        rowcount = cursor.rowcount
        cursor.close()
        return rowcount

    async def query(self, sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Execute SELECT query within the transaction.

        Args:
            sql: SELECT statement
            params: Dictionary of parameter values

        Returns:
            List of row dictionaries
        """
        cursor = self._conn.cursor()
        cursor.execute(sql, params or {})
        columns = [col[0] for col in cursor.description]
        rows = cursor.fetchall()
        result = [dict(zip(columns, row)) for row in rows]
        cursor.close()
        return result

    async def query_one(self, sql: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Execute SELECT query and return first row.

        Args:
            sql: SELECT statement
            params: Dictionary of parameter values

        Returns:
            Row dictionary or None
        """
        cursor = self._conn.cursor()
        cursor.execute(sql, params or {})
        columns = [col[0] for col in cursor.description]
        row = cursor.fetchone()
        cursor.close()
        if row is None:
            return None
        return dict(zip(columns, row))

    async def get_next_sequence(self, sequence_name: str) -> int:
        """
        Get next value from Oracle sequence within transaction.

        Args:
            sequence_name: Name of the sequence

        Returns:
            Next sequence value
        """
        cursor = self._conn.cursor()
        cursor.execute(f"SELECT {sequence_name}.NEXTVAL FROM DUAL")
        row = cursor.fetchone()
        cursor.close()
        if row is None:
            raise Exception(f"Failed to get sequence value: {sequence_name}")
        return int(row[0])


class DatabasePool:
    """
    Oracle connection pool manager.

    Provides connection pooling and query execution methods
    with automatic connection management and error handling.
    """

    def __init__(
        self,
        user: str,
        dsn: str,
        pool_min: int = 5,
        pool_max: int = 20,
        pool_increment: int = 2,
        password: Optional[str] = None
    ):
        """
        Initialize database pool configuration.

        Args:
            user: Oracle username
            dsn: Oracle DSN (e.g., "host:port/service")
            pool_min: Minimum pool connections
            pool_max: Maximum pool connections
            pool_increment: Pool growth increment
            password: Oracle password (falls back to EPP_DB_PASSWORD env var)
        """
        self.user = user
        self.dsn = dsn
        self.pool_min = pool_min
        self.pool_max = pool_max
        self.pool_increment = pool_increment
        self._password = password or os.environ.get("EPP_DB_PASSWORD")
        self._pool: Optional[oracledb.ConnectionPool] = None

    async def initialize(self) -> None:
        """
        Initialize the connection pool.

        Raises:
            ConnectionError: If pool creation fails
        """
        if self._pool is not None:
            logger.warning("Pool already initialized")
            return

        if not self._password:
            raise ConnectionError(
                "Database password not configured. "
                "Set EPP_DB_PASSWORD environment variable."
            )

        try:
            logger.info(f"Creating Oracle connection pool: {self.user}@{self.dsn}")
            logger.info(f"Pool size: min={self.pool_min}, max={self.pool_max}")

            # Use synchronous pool creation (more stable)
            self._pool = oracledb.create_pool(
                user=self.user,
                password=self._password,
                dsn=self.dsn,
                min=self.pool_min,
                max=self.pool_max,
                increment=self.pool_increment,
                getmode=oracledb.POOL_GETMODE_WAIT,
                homogeneous=True
            )

            # Test connection
            conn = self._pool.acquire()
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM DUAL")
            cursor.close()
            self._pool.release(conn)

            logger.info("Database pool initialized successfully")

        except oracledb.Error as e:
            error_msg = f"Failed to create database pool: {e}"
            logger.error(error_msg)
            raise ConnectionError(error_msg) from e

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool is not None:
            try:
                self._pool.close()
                logger.info("Database pool closed")
            except Exception as e:
                logger.error(f"Error closing pool: {e}")
            finally:
                self._pool = None

    @asynccontextmanager
    async def acquire(self):
        """
        Acquire a connection from the pool.

        Usage:
            async with pool.acquire() as conn:
                cursor = conn.cursor()
                ...

        Yields:
            oracledb.Connection

        Raises:
            ConnectionError: If pool not initialized or acquire fails
        """
        if self._pool is None:
            raise ConnectionError("Database pool not initialized")

        conn = None
        try:
            conn = self._pool.acquire()
            yield conn
        except oracledb.Error as e:
            logger.error(f"Error acquiring connection: {e}")
            raise ConnectionError(f"Failed to acquire connection: {e}") from e
        finally:
            if conn is not None:
                try:
                    self._pool.release(conn)
                except Exception as e:
                    logger.error(f"Error releasing connection: {e}")

    @asynccontextmanager
    async def transaction(self):
        """
        Acquire a connection with transaction semantics.

        Commits on successful exit, rolls back on exception.

        Usage:
            async with pool.transaction() as conn:
                cursor = conn.cursor()
                cursor.execute(...)
                # auto-commits on exit, rolls back on exception

        Yields:
            TransactionConnection wrapper with execute method

        Raises:
            ConnectionError: If pool not initialized or acquire fails
        """
        if self._pool is None:
            raise ConnectionError("Database pool not initialized")

        conn = None
        try:
            conn = self._pool.acquire()
            tx_conn = TransactionConnection(conn)
            yield tx_conn
            conn.commit()
        except Exception as e:
            if conn is not None:
                try:
                    conn.rollback()
                except Exception:
                    pass
            raise
        finally:
            if conn is not None:
                try:
                    self._pool.release(conn)
                except Exception as e:
                    logger.error(f"Error releasing connection: {e}")

    async def execute(
        self,
        sql: str,
        params: Optional[Dict[str, Any]] = None,
        commit: bool = True
    ) -> int:
        """
        Execute a single SQL statement.

        Args:
            sql: SQL statement with named parameters (:param_name)
            params: Dictionary of parameter values
            commit: Whether to commit the transaction

        Returns:
            Number of rows affected

        Raises:
            QueryError: If execution fails
        """
        async with self.acquire() as conn:
            try:
                cursor = conn.cursor()
                cursor.execute(sql, params or {})
                rowcount = cursor.rowcount

                if commit:
                    conn.commit()

                cursor.close()
                return rowcount

            except oracledb.Error as e:
                conn.rollback()
                logger.error(f"Query execution failed: {e}")
                logger.debug(f"SQL: {sql}")
                logger.debug(f"Params: {params}")
                raise QueryError(f"Query execution failed: {e}") from e

    async def execute_many(
        self,
        sql: str,
        params_list: List[Dict[str, Any]],
        commit: bool = True
    ) -> int:
        """
        Execute a SQL statement with multiple parameter sets.

        Args:
            sql: SQL statement with named parameters
            params_list: List of parameter dictionaries
            commit: Whether to commit the transaction

        Returns:
            Total rows affected

        Raises:
            QueryError: If execution fails
        """
        async with self.acquire() as conn:
            try:
                cursor = conn.cursor()
                cursor.executemany(sql, params_list)
                rowcount = cursor.rowcount

                if commit:
                    conn.commit()

                cursor.close()
                return rowcount

            except oracledb.Error as e:
                conn.rollback()
                logger.error(f"Batch execution failed: {e}")
                raise QueryError(f"Batch execution failed: {e}") from e

    async def query(
        self,
        sql: str,
        params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute a SELECT query and return all rows.

        Args:
            sql: SELECT statement with named parameters
            params: Dictionary of parameter values

        Returns:
            List of dictionaries (column_name: value)

        Raises:
            QueryError: If query fails
        """
        async with self.acquire() as conn:
            try:
                cursor = conn.cursor()
                cursor.execute(sql, params or {})

                # Get column names
                columns = [col[0] for col in cursor.description]

                # Fetch all rows as dictionaries
                rows = cursor.fetchall()
                result = [dict(zip(columns, row)) for row in rows]

                cursor.close()
                return result

            except oracledb.Error as e:
                logger.error(f"Query failed: {e}")
                logger.debug(f"SQL: {sql}")
                raise QueryError(f"Query failed: {e}") from e

    async def query_one(
        self,
        sql: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Execute a SELECT query and return first row.

        Args:
            sql: SELECT statement with named parameters
            params: Dictionary of parameter values

        Returns:
            Dictionary of column_name: value, or None if no rows

        Raises:
            QueryError: If query fails
        """
        async with self.acquire() as conn:
            try:
                cursor = conn.cursor()
                cursor.execute(sql, params or {})

                # Get column names
                columns = [col[0] for col in cursor.description]

                # Fetch one row
                row = cursor.fetchone()
                cursor.close()

                if row is None:
                    return None

                return dict(zip(columns, row))

            except oracledb.Error as e:
                logger.error(f"Query failed: {e}")
                raise QueryError(f"Query failed: {e}") from e

    async def query_value(
        self,
        sql: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Execute a SELECT query and return single value.

        Args:
            sql: SELECT statement returning single column/row
            params: Dictionary of parameter values

        Returns:
            Single value or None

        Raises:
            QueryError: If query fails
        """
        async with self.acquire() as conn:
            try:
                cursor = conn.cursor()
                cursor.execute(sql, params or {})

                row = cursor.fetchone()
                cursor.close()

                if row is None:
                    return None

                return row[0]

            except oracledb.Error as e:
                logger.error(f"Query failed: {e}")
                raise QueryError(f"Query failed: {e}") from e

    async def execute_plsql(
        self,
        sql: str,
        params: Dict[str, Any],
        commit: bool = True
    ) -> Dict[str, Any]:
        """
        Execute a PL/SQL block with IN/OUT parameters.

        Args:
            sql: PL/SQL block with named parameters
            params: Dictionary of parameter values (OUT params should be None)
            commit: Whether to commit the transaction

        Returns:
            Dictionary with output parameter values

        Raises:
            QueryError: If execution fails
        """
        async with self.acquire() as conn:
            try:
                cursor = conn.cursor()

                # Create variables for OUT parameters
                out_vars = {}
                bind_params = {}
                for key, value in params.items():
                    if value is None:
                        # This is an OUT parameter - create a variable
                        out_vars[key] = cursor.var(int)
                        bind_params[key] = out_vars[key]
                    else:
                        bind_params[key] = value

                cursor.execute(sql, bind_params)

                if commit:
                    conn.commit()

                # Get values from OUT variables
                result = {}
                for key, var in out_vars.items():
                    result[key] = var.getvalue()

                cursor.close()
                return result

            except oracledb.Error as e:
                conn.rollback()
                logger.error(f"PL/SQL execution failed: {e}")
                logger.debug(f"SQL: {sql}")
                logger.debug(f"Params: {params}")
                raise QueryError(f"PL/SQL execution failed: {e}") from e

    async def get_next_sequence(self, sequence_name: str) -> int:
        """
        Get next value from Oracle sequence.

        Args:
            sequence_name: Name of the sequence

        Returns:
            Next sequence value

        Raises:
            QueryError: If sequence access fails
        """
        sql = f"SELECT {sequence_name}.NEXTVAL FROM DUAL"
        value = await self.query_value(sql)
        if value is None:
            raise QueryError(f"Failed to get sequence value: {sequence_name}")
        return int(value)

    async def call_procedure(
        self,
        name: str,
        params: Optional[List[Any]] = None,
        commit: bool = True
    ) -> List[Any]:
        """
        Call an Oracle stored procedure.

        Args:
            name: Procedure name
            params: List of parameters (in/out)
            commit: Whether to commit

        Returns:
            List of output parameter values

        Raises:
            QueryError: If call fails
        """
        async with self.acquire() as conn:
            try:
                cursor = conn.cursor()
                result = cursor.callproc(name, params or [])

                if commit:
                    conn.commit()

                cursor.close()
                return result

            except oracledb.Error as e:
                conn.rollback()
                logger.error(f"Procedure call failed: {e}")
                raise QueryError(f"Procedure call failed: {e}") from e

    @property
    def pool_stats(self) -> Dict[str, int]:
        """
        Get connection pool statistics.

        Returns:
            Dictionary with pool stats
        """
        if self._pool is None:
            return {"status": "not_initialized"}

        return {
            "open": self._pool.opened,
            "busy": self._pool.busy,
            "available": self._pool.opened - self._pool.busy,
            "min": self._pool.min,
            "max": self._pool.max
        }


# Global pool instance
_pool: Optional[DatabasePool] = None


async def initialize_pool(config: Dict[str, Any]) -> DatabasePool:
    """
    Initialize global database pool from config.

    Args:
        config: Oracle configuration dictionary with keys:
            - user: Oracle username
            - dsn: Oracle DSN
            - pool_min: Minimum connections
            - pool_max: Maximum connections
            - pool_increment: Growth increment

    Returns:
        Initialized DatabasePool instance
    """
    global _pool

    _pool = DatabasePool(
        user=config["user"],
        dsn=config["dsn"],
        pool_min=config.get("pool_min", 5),
        pool_max=config.get("pool_max", 20),
        pool_increment=config.get("pool_increment", 2)
    )

    await _pool.initialize()
    return _pool


async def get_pool() -> DatabasePool:
    """
    Get global database pool.

    Returns:
        DatabasePool instance

    Raises:
        ConnectionError: If pool not initialized
    """
    if _pool is None:
        raise ConnectionError("Database pool not initialized")
    return _pool


async def close_pool() -> None:
    """Close global database pool."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
