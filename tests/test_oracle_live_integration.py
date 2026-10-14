"""Live Oracle Integration Test using Oracle Container or Dedicated Test Instance.
Reproduces real ORA-00054 (resource busy and acquire with NOWAIT specified)
between two concurrent live database sessions, triggers LockDiagnosticsEngine
against dynamic V$ views, and asserts the root blocker is accurately isolated.

Safety & Hygiene Guarantees:
1. Requires explicit test credentials (no insecure defaults to SYSTEM/default passwords).
2. Uses ephemeral, uniquely named test tables to prevent destroying existing schema tables.
3. Synchronizes configuration environment variables between test runner and config modules.
4. Wraps connection and cursor lifecycles in strict try/finally blocks and per-test tearDown
   to prevent leaking uncommitted blocker locks on failure.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import sys
import time
import unittest
import uuid
from typing import Any

import pytest

# Add workspace root to sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ascp_agent.config import OracleConfig
from ascp_agent.lock_engine import LockDiagnosticsEngine, OracleConnectionPool

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_REAL_ORACLE", "false").lower() != "true",
    reason="Skipping live Oracle integration tests by default (set RUN_REAL_ORACLE=true with explicit credentials)",
)


def get_live_oracle_config() -> OracleConfig | None:
    """Retrieve database connection settings from environment.
    Requires explicit credentials; rejects predictable default fallbacks.
    Synchronizes environment variables so ascp_agent.config stays consistent.
    """
    username = os.environ.get("ORACLE_TEST_USER") or os.environ.get("ORACLE_USER")
    password = os.environ.get("ORACLE_TEST_PASSWORD") or os.environ.get("ORACLE_PASSWORD")

    # Fail-closed: require explicit credentials; do not default to SYSTEM or hardcoded passwords
    if not username or not password:
        return None

    host = os.environ.get("ORACLE_TEST_HOST") or os.environ.get("ORACLE_HOST", "localhost")
    port = int(os.environ.get("ORACLE_TEST_PORT") or os.environ.get("ORACLE_PORT", "1521"))
    service_name = os.environ.get("ORACLE_TEST_SERVICE") or os.environ.get("ORACLE_SERVICE_NAME", "FREEPDB1")

    # Synchronize configuration environment variables to avoid configuration mismatch
    os.environ["ORACLE_USER"] = username
    os.environ["ORACLE_PASSWORD"] = password
    os.environ["ORACLE_HOST"] = host
    os.environ["ORACLE_PORT"] = str(port)
    os.environ["ORACLE_SERVICE_NAME"] = service_name
    os.environ["ORACLE_TEST_USER"] = username
    os.environ["ORACLE_TEST_PASSWORD"] = password

    return OracleConfig(
        host=host,
        port=port,
        service_name=service_name,
        username=username,
        password=password,
        min_pool_size=1,
        max_pool_size=5,
        pool_increment=1,
        use_simulation=False,
    )


def is_oracle_live_available() -> bool:
    """Probes if a live Oracle database is reachable with provided credentials."""
    try:
        oracledb = importlib.import_module("oracledb")
    except ImportError:
        return False

    cfg = get_live_oracle_config()
    if not cfg:
        return False

    try:
        conn = oracledb.connect(
            user=cfg.username,
            password=cfg.password,
            host=cfg.host,
            port=cfg.port,
            service_name=cfg.service_name,
            tcp_connect_timeout=2.0,
        )
        conn.close()
        return True
    except (getattr(oracledb, "DatabaseError", Exception), OSError, TimeoutError):
        return False


class TestOracleLiveIntegration(unittest.TestCase):
    """End-to-end integration test validating Lock Engine against live Oracle instance."""

    test_table_name: str = ""
    config: OracleConfig | None = None
    oracledb: Any = None

    @classmethod
    def setUpClass(cls):
        if os.getenv("RUN_REAL_ORACLE", "false").lower() != "true":
            raise unittest.SkipTest("Skipping live Oracle integration tests by default (set RUN_REAL_ORACLE=true)")

        cls.config = get_live_oracle_config()
        if not cls.config:
            raise unittest.SkipTest(
                "Live Oracle credentials not provided in environment. "
                "Set ORACLE_USER/ORACLE_TEST_USER and ORACLE_PASSWORD/ORACLE_TEST_PASSWORD."
            )

        if not is_oracle_live_available():
            raise unittest.SkipTest("Live Oracle database not accessible at configured endpoint.")

        cls.oracledb = importlib.import_module("oracledb")

        # Use an ephemeral, uniquely named test table to prevent destroying existing tables
        cls.test_table_name = f"TEST_MSC_DEM_{uuid.uuid4().hex[:8].upper()}"

        # Setup dedicated test table in current test user's schema
        with cls.oracledb.connect(
            user=cls.config.username,
            password=cls.config.password,
            host=cls.config.host,
            port=cls.config.port,
            service_name=cls.config.service_name,
        ) as conn, conn.cursor() as cur:
            # Verify ownership if table already exists in user's schema
            cur.execute("SELECT table_name FROM user_tables WHERE table_name = :tname", [cls.test_table_name])
            if cur.fetchone():
                cur.execute(f"DROP TABLE {cls.test_table_name} PURGE")  # nosec B608

            create_sql = f"""
                CREATE TABLE {cls.test_table_name} (
                    DEMAND_ID NUMBER PRIMARY KEY,
                    INVENTORY_ITEM_ID NUMBER,
                    ORGANIZATION_ID NUMBER,
                    DEMAND_DATE DATE,
                    QUANTITY NUMBER,
                    PROCESS_STATUS NUMBER
                )
            """
            cur.execute(create_sql)  # nosec B608
            cur.execute(f"INSERT INTO {cls.test_table_name} VALUES (101, 10001, 204, SYSDATE, 50, 1)")  # nosec B608
            conn.commit()

    @classmethod
    def tearDownClass(cls):
        if cls.config and cls.test_table_name and is_oracle_live_available():
            try:
                with cls.oracledb.connect(
                    user=cls.config.username,
                    password=cls.config.password,
                    host=cls.config.host,
                    port=cls.config.port,
                    service_name=cls.config.service_name,
                ) as conn, conn.cursor() as cur:
                    cur.execute(f"DROP TABLE {cls.test_table_name} PURGE")  # nosec B608
                    conn.commit()
            except Exception:  # noqa: BLE001, S110
                pass

    def setUp(self):
        self._active_connections = []

    def tearDown(self):
        """Guarantee cleanup of all open connections and release locks even if test asserts fail."""
        for conn in self._active_connections:
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001, S110
                pass
            try:
                conn.close()
            except Exception:  # noqa: BLE001, S110
                pass
        self._active_connections.clear()

    def _open_tracked_connection(self):
        conn = self.oracledb.connect(
            user=self.config.username,
            password=self.config.password,
            host=self.config.host,
            port=self.config.port,
            service_name=self.config.service_name,
        )
        self._active_connections.append(conn)
        return conn

    def test_reproduce_ora_00054_and_isolate_root_blocker(self):
        """Simulates real dual-session contention:
        1. Session 1 locks unique test table in Exclusive Mode (Mode 6).
        2. Session 2 attempts NOWAIT lock and triggers ORA-00054.
        3. LockDiagnosticsEngine inspects live V$ dynamic views.
        4. Asserts Session 1 is correctly isolated as root blocker.
        5. Cleans up all connections in finally / tearDown.
        """
        pool = None
        conn_blocker = None
        conn_worker = None
        try:
            # Session 1: Blocker holding uncommitted Mode 6 Exclusive Table Lock
            conn_blocker = self._open_tracked_connection()
            cur_blocker = conn_blocker.cursor()
            cur_blocker.execute(f"LOCK TABLE {self.test_table_name} IN EXCLUSIVE MODE")  # nosec B608

            # Acquire blocker SID after acquiring lock
            cur_blocker.execute("SELECT SYS_CONTEXT('USERENV', 'SID') FROM DUAL")
            blocker_sid = int(cur_blocker.fetchone()[0])

            # Session 2: Victim worker attempting lock with NOWAIT
            conn_worker = self._open_tracked_connection()
            cur_worker = conn_worker.cursor()

            # Trigger ORA-00054
            ora_54_caught = False
            try:
                cur_worker.execute(f"LOCK TABLE {self.test_table_name} IN EXCLUSIVE MODE NOWAIT")  # nosec B608
            except self.oracledb.DatabaseError as exc:
                error_obj = exc.args[0] if exc.args else None
                if (error_obj and getattr(error_obj, "code", None) == 54) or "ORA-00054" in str(exc):
                    ora_54_caught = True

            self.assertTrue(ora_54_caught, "Failed to reproduce real ORA-00054 against live Oracle instance!")

            # Step 3: Run ASCP LockDiagnosticsEngine against the live database with retry
            pool = OracleConnectionPool(self.config)
            engine = LockDiagnosticsEngine(pool=pool, config=self.config)

            root_blocker = None
            telemetry = None
            for _ in range(10):  # Retry for up to ~10 seconds to tolerate propagation delay
                telemetry = engine.execute_hierarchical_lock_query(bypass_cache=True)
                root_blocker = engine.isolate_root_blocker(telemetry)
                if root_blocker:
                    break
                time.sleep(1)

            # Diagnostic fallback logging if root blocker is missing
            if root_blocker is None:
                try:
                    logger.debug("Telemetry dump: %s", json.dumps(telemetry, default=str, indent=2))
                except (TypeError, ValueError):
                    logger.debug("Telemetry: %s", str(telemetry))

            # Step 4: Assertions on real lock telemetry
            self.assertIsNotNone(root_blocker, "Lock Engine failed to isolate root blocker from live V$ views")
            self.assertEqual(
                root_blocker.get("sid"),
                blocker_sid,
                f"Expected blocker SID {blocker_sid}, got {root_blocker.get('sid')}",
            )
            self.assertIn(
                self.test_table_name.upper(),
                str(root_blocker.get("object_name", "")).upper(),
                f"Expected object {self.test_table_name} in lock telemetry",
            )
            self.assertEqual(root_blocker.get("locked_mode"), 6, "Expected Lock Mode 6 (Exclusive)")

        finally:
            if pool:
                try:
                    pool.close()
                except Exception:  # noqa: BLE001, S110
                    pass


if __name__ == "__main__":
    unittest.main()
