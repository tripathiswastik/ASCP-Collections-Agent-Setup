"""
Python Version: 3.10+ (Target: Python 3.10, 3.11, 3.12)
Purpose: Production Oracle Database connection pooling and query executor with automatic simulation fallback.
Runs-in: Local development shell, CI test runner, or autonomous agent evaluation runtime.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from typing import Any, AsyncGenerator, Dict, Generator, List, Optional, Tuple

from ascp_agent.config import OracleConfig, DEFAULT_CONFIG

logger = logging.getLogger(__name__)


class OracleQueryError(RuntimeError):
    """Raised when live Oracle database query execution fails."""
    pass


@dataclass
class QueryResult:
    """Standardized query execution result container."""
    columns: List[str]
    rows: List[Tuple[Any, ...]]
    row_count: int
    execution_time_ms: float
    is_simulated: bool = False

    def to_dicts(self) -> List[Dict[str, Any]]:
        """Converts tabular rows into list of dictionaries keyed by lowercase column names."""
        cols = [c.lower() for c in self.columns]
        return [dict(zip(cols, row)) for row in self.rows]


class OracleConnectionPool:
    """Enterprise connection pool manager for Oracle Database with seamless simulation fallback.

    Supports python-oracledb in thin mode (default, zero client libraries required)
    and provides unified synchronous and asynchronous context managers.
    """

    def __init__(self, config: Optional[OracleConfig] = None):
        self.config: OracleConfig = config or DEFAULT_CONFIG.oracle
        self._oracledb: Optional[Any] = None
        self._sync_pool: Optional[Any] = None
        self._async_pool: Optional[Any] = None
        self._is_connected: bool = False
        self._driver_loaded: bool = False
        self._init_driver()

    def _init_driver(self) -> None:
        """Dynamically imports python-oracledb if installed."""
        try:
            import importlib
            self._oracledb = importlib.import_module("oracledb")
            self._driver_loaded = True
        except ImportError:
            self._oracledb = None
            self._driver_loaded = False
            logger.info("python-oracledb driver not installed. Defaulting to simulation mode.")

    @property
    def is_simulation(self) -> bool:
        """Returns True if explicitly configured for simulation or if driver/credentials unavailable."""
        return (
            self.config.use_simulation
            or not self._driver_loaded
            or self.config.host == "ebs-db.corp.internal"  # Default mocked host
        )

    def initialize_sync_pool(self, min_conn: int = 1, max_conn: int = 5) -> bool:
        """Initializes synchronous connection pool. Returns True on success, False on fallback."""
        if self.is_simulation:
            return False

        if self._sync_pool is not None:
            return True

        try:
            assert self._oracledb is not None
            self._sync_pool = self._oracledb.create_pool(
                user=self.config.username,
                password=self.config.password,
                host=self.config.host,
                port=self.config.port,
                service_name=self.config.service_name,
                min=min_conn,
                max=max_conn,
                increment=1
            )
            self._is_connected = True
            logger.info("Oracle synchronous connection pool created successfully.")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Oracle connection pool ({e}). Operating in simulation fallback.")
            self._sync_pool = None
            self._is_connected = False
            return False

    async def initialize_async_pool(self, min_conn: int = 1, max_conn: int = 5) -> bool:
        """Initializes asynchronous connection pool. Returns True on success, False on fallback."""
        if self.is_simulation:
            return False

        if self._async_pool is not None:
            return True

        try:
            assert self._oracledb is not None
            self._async_pool = await self._oracledb.create_pool_async(
                user=self.config.username,
                password=self.config.password,
                host=self.config.host,
                port=self.config.port,
                service_name=self.config.service_name,
                min=min_conn,
                max=max_conn,
                increment=1
            )
            self._is_connected = True
            logger.info("Oracle asynchronous connection pool created successfully.")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Oracle async pool ({e}). Operating in simulation fallback.")
            self._async_pool = None
            self._is_connected = False
            return False

    @contextmanager
    def get_connection(self) -> Generator[Any, None, None]:
        """Synchronous connection context manager with auto-acquire and release."""
        if self._sync_pool is None and not self.is_simulation:
            self.initialize_sync_pool()

        if self._sync_pool is not None:
            conn = self._sync_pool.acquire()
            try:
                yield conn
            finally:
                self._sync_pool.release(conn)
        else:
            # Yield None in simulation mode; queries will trigger simulation fallbacks
            yield None

    @asynccontextmanager
    async def get_async_connection(self) -> AsyncGenerator[Any, None]:
        """Asynchronous connection context manager."""
        if self._async_pool is None and not self.is_simulation:
            await self.initialize_async_pool()

        if self._async_pool is not None:
            conn = await self._async_pool.acquire()
            try:
                yield conn
            finally:
                await self._async_pool.release(conn)
        else:
            yield None

    def execute_query(
        self,
        sql: str,
        params: Optional[Dict[str, Any]] = None,
        timeout_sec: float = 30.0
    ) -> QueryResult:
        """Executes a SQL query synchronously with timing metrics and auto-recovery."""
        start_time = time.time()
        params = params or {}

        if not self.is_simulation:
            try:
                with self.get_connection() as conn:
                    if conn is None:
                        raise OracleQueryError("Live Oracle database unreachable; no connection available.")
                    try:
                        conn.call_timeout = int(timeout_sec * 1000)
                    except AttributeError:
                        pass
                    with conn.cursor() as cursor:
                        cursor.execute(sql, params)
                        cols = [c[0] for c in cursor.description] if cursor.description else []
                        rows = cursor.fetchall()
                        elapsed = (time.time() - start_time) * 1000.0
                        return QueryResult(
                            columns=cols,
                            rows=rows,
                            row_count=len(rows),
                            execution_time_ms=round(elapsed, 2),
                            is_simulated=False
                        )
            except Exception as exc:
                logger.exception("Live Oracle query failed")
                raise OracleQueryError("Live Oracle query failed") from exc

        # Fallback simulation result
        elapsed = (time.time() - start_time) * 1000.0
        return QueryResult(
            columns=["STATUS", "MESSAGE"],
            rows=[("SIMULATION", "Query simulated or database unreachable.")],
            row_count=1,
            execution_time_ms=round(elapsed, 2),
            is_simulated=True
        )

    async def execute_query_async(
        self,
        sql: str,
        params: Optional[Dict[str, Any]] = None
    ) -> QueryResult:
        """Executes a non-blocking asynchronous SQL query."""
        start_time = time.time()
        params = params or {}

        if not self.is_simulation:
            try:
                async with self.get_async_connection() as conn:
                    if conn is None:
                        raise OracleQueryError("Live async Oracle database unreachable; no connection available.")
                    cursor = conn.cursor()
                    try:
                        await cursor.execute(sql, params)
                        cols = [c[0] for c in cursor.description] if cursor.description else []
                        rows = await cursor.fetchall()
                        elapsed = (time.time() - start_time) * 1000.0
                        return QueryResult(
                            columns=cols,
                            rows=rows,
                            row_count=len(rows),
                            execution_time_ms=round(elapsed, 2),
                            is_simulated=False
                        )
                    finally:
                        if hasattr(cursor, "close"):
                            res = cursor.close()
                            if asyncio.iscoroutine(res):
                                await res
            except Exception as exc:
                logger.exception("Live async Oracle query failed")
                raise OracleQueryError("Live async Oracle query failed") from exc

        elapsed = (time.time() - start_time) * 1000.0
        return QueryResult(
            columns=["STATUS", "MESSAGE"],
            rows=[("SIMULATION", "Async query simulated or database unreachable.")],
            row_count=1,
            execution_time_ms=round(elapsed, 2),
            is_simulated=True
        )

    def ping(self) -> Dict[str, Any]:
        """Performs health check ping against database connection pool."""
        if self.is_simulation:
            return {
                "alive": True,
                "mode": "SIMULATION",
                "driver": "built-in simulation engine",
                "latency_ms": 0.5
            }

        start = time.time()
        try:
            res = self.execute_query("SELECT 1 FROM DUAL")
            latency = (time.time() - start) * 1000.0
            return {
                "alive": not res.is_simulated,
                "mode": "ORACLE_LIVE",
                "driver": "python-oracledb (thin)",
                "latency_ms": round(latency, 2)
            }
        except Exception as e:
            return {
                "alive": False,
                "mode": "DISCONNECTED",
                "error": str(e),
                "latency_ms": 0.0
            }

    def close(self) -> None:
        """Closes all active pools and releases resources."""
        if self._sync_pool is not None:
            try:
                self._sync_pool.close()
            except Exception:
                pass
            self._sync_pool = None

        if self._async_pool is not None:
            try:
                asyncio.run(self._async_pool.close())
            except Exception:
                pass
            self._async_pool = None

        self._is_connected = False


# Module-level default singleton pool
_GLOBAL_POOL: Optional[OracleConnectionPool] = None


def get_oracle_pool(config: Optional[OracleConfig] = None) -> OracleConnectionPool:
    """Returns singleton Oracle connection pool instance."""
    global _GLOBAL_POOL
    if _GLOBAL_POOL is None:
        _GLOBAL_POOL = OracleConnectionPool(config)
    return _GLOBAL_POOL
