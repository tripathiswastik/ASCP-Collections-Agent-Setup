"""Live Oracle Integration Test using Oracle Free Container (gvenzl/oracle-free).
Reproduces real ORA-00054 (resource busy and acquire with NOWAIT specified)
between two concurrent live database sessions, triggers LockDiagnosticsEngine
against dynamic V$ views, and asserts the root blocker is accurately isolated.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import time
import unittest

import pytest

# Add workspace root to sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ascp_agent.config import OracleConfig
from ascp_agent.lock_engine import LockDiagnosticsEngine, OracleConnectionPool

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_REAL_ORACLE", "false").lower() != "true",
    reason="Skipping live Oracle integration tests in CI by default"
)


def get_live_oracle_config() -> OracleConfig | None:
    """Retrieve database connection settings from environment or defaults."""
    host = os.environ.get("ORACLE_TEST_HOST", "localhost")
    port = int(os.environ.get("ORACLE_TEST_PORT", "1521"))
    service_name = os.environ.get("ORACLE_TEST_SERVICE", "FREEPDB1")
    username = os.environ.get("ORACLE_TEST_USER", "system")
    password = os.environ.get("ORACLE_TEST_PASSWORD", "OraclePassword123!")

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
    """Probes if a live Oracle database is reachable."""
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
            tcp_connect_timeout=2.0
        )
        conn.close()
        return True
    except (getattr(oracledb, "DatabaseError", Exception), OSError, TimeoutError):
        return False


class TestOracleLiveIntegration(unittest.TestCase):
    """End-to-end integration test validating Lock Engine against live Oracle instance."""

    @classmethod
    def setUpClass(cls):
        if os.getenv("RUN_REAL_ORACLE", "false").lower() != "true":
            raise unittest.SkipTest("Skipping live Oracle integration tests in CI by default (set RUN_REAL_ORACLE=true)")

        if not is_oracle_live_available():
            raise unittest.SkipTest("Live Oracle database not accessible (skip for non-container CI runs)")

        cls.config = get_live_oracle_config()
        cls.oracledb = importlib.import_module("oracledb")

        # Setup dedicated test table
        with cls.oracledb.connect(
            user=cls.config.username,
            password=cls.config.password,
            host=cls.config.host,
            port=cls.config.port,
            service_name=cls.config.service_name
        ) as conn, conn.cursor() as cur:
            try:
                cur.execute("DROP TABLE TEST_MSC_ST_DEMANDS PURGE")
            except Exception:  # noqa: BLE001, S110 -- table may not exist yet on initial setup
                pass
            cur.execute("""
                    CREATE TABLE TEST_MSC_ST_DEMANDS (
                        DEMAND_ID NUMBER PRIMARY KEY,
                        INVENTORY_ITEM_ID NUMBER,
                        ORGANIZATION_ID NUMBER,
                        DEMAND_DATE DATE,
                        QUANTITY NUMBER,
                        PROCESS_STATUS NUMBER
                    )
                """)
            cur.execute("INSERT INTO TEST_MSC_ST_DEMANDS VALUES (101, 10001, 204, SYSDATE, 50, 1)")
            conn.commit()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "config") and is_oracle_live_available():
            try:
                with cls.oracledb.connect(
                    user=cls.config.username,
                    password=cls.config.password,
                    host=cls.config.host,
                    port=cls.config.port,
                    service_name=cls.config.service_name
                ) as conn, conn.cursor() as cur:
                    cur.execute("DROP TABLE TEST_MSC_ST_DEMANDS PURGE")
                    conn.commit()
            except Exception:  # noqa: BLE001, S110 -- ignore drop error on teardown
                pass

    def test_reproduce_ora_00054_and_isolate_root_blocker(self):
        """Simulates real dual-session contention:
        1. Session 1 locks TEST_MSC_ST_DEMANDS in Exclusive Mode (Mode 6).
        2. Session 2 attempts NOWAIT lock and triggers ORA-00054.
        3. LockDiagnosticsEngine inspects live V$ dynamic views.
        4. Asserts Session 1 is correctly isolated as root blocker.
        """
        # Session 1: Blocker
        conn_blocker = self.oracledb.connect(
            user=self.config.username,
            password=self.config.password,
            host=self.config.host,
            port=self.config.port,
            service_name=self.config.service_name
        )

        cur_blocker = conn_blocker.cursor()

        # Step 1: Hold uncommitted Mode 6 Exclusive Table Lock
        cur_blocker.execute("LOCK TABLE TEST_MSC_ST_DEMANDS IN EXCLUSIVE MODE")

        # Acquire blocker SID after acquiring lock
        cur_blocker.execute("SELECT SYS_CONTEXT('USERENV', 'SID') FROM DUAL")
        blocker_sid = int(cur_blocker.fetchone()[0])

        # Session 2: Victim worker attempting lock with NOWAIT
        conn_worker = self.oracledb.connect(
            user=self.config.username,
            password=self.config.password,
            host=self.config.host,
            port=self.config.port,
            service_name=self.config.service_name
        )
        cur_worker = conn_worker.cursor()

        # Step 2: Trigger ORA-00054
        ora_54_caught = False
        try:
            cur_worker.execute("LOCK TABLE TEST_MSC_ST_DEMANDS IN EXCLUSIVE MODE NOWAIT")
        except self.oracledb.DatabaseError as exc:
            error_obj, = exc.args
            if error_obj.code == 54 or "ORA-00054" in str(exc):
                ora_54_caught = True

        self.assertTrue(ora_54_caught, "Failed to reproduce real ORA-00054 against live Oracle container!")

        # Step 3: Run ASCP LockDiagnosticsEngine against the live database with retries
        pool = OracleConnectionPool(self.config)
        engine = LockDiagnosticsEngine(pool=pool, config=self.config)

        # Bypass cache to perform live inspection of V$ views with retry loop
        root_blocker = None
        telemetry = None
        for _ in range(10):  # Retry for up to ~10 seconds to tolerate propagation delay
            telemetry = engine.execute_hierarchical_lock_query(bypass_cache=True)
            root_blocker = engine.isolate_root_blocker(telemetry)
            if root_blocker:
                break
            time.sleep(1)

        # If still missing, dump telemetry and raw dynamic views for debugging
        if root_blocker is None:
            try:
                print("DEBUG: telemetry =", json.dumps(telemetry, default=str, indent=2))
            except (TypeError, ValueError):
                print("DEBUG: telemetry (str) =", str(telemetry))
            try:
                with pool.get_connection() as diag_conn, diag_conn.cursor() as diag_cur:
                    diag_cur.execute("SELECT sid, serial#, username, status, module FROM v$session WHERE username IS NOT NULL")
                    print("DEBUG: v$session rows:", diag_cur.fetchall())
                    diag_cur.execute("SELECT session_id, object_id, locked_mode FROM v$locked_object")
                    print("DEBUG: v$locked_object rows:", diag_cur.fetchall())
                    diag_cur.execute("SELECT sid, type, id1, id2, lmode, request, block FROM v$lock WHERE type IN ('TM', 'TX')")
                    print("DEBUG: v$lock rows:", diag_cur.fetchall())
            except Exception as diag_err:  # noqa: BLE001 -- diagnostic query fallback
                print("DEBUG: failed to query diagnostic views:", diag_err)

        # Step 4: Assertions on real lock telemetry
        self.assertIsNotNone(root_blocker, "Lock Engine failed to isolate root blocker from live V$ views")
        self.assertEqual(root_blocker.get("sid"), blocker_sid, f"Expected blocker SID {blocker_sid}, got {root_blocker.get('sid')}")
        self.assertIn("TEST_MSC_ST_DEMANDS", str(root_blocker.get("object_name")).upper())
        self.assertEqual(root_blocker.get("locked_mode"), 6, "Expected Lock Mode 6 (Exclusive)")

        # Cleanup active sessions
        cur_blocker.execute("ROLLBACK")
        cur_blocker.close()
        conn_blocker.close()

        cur_worker.close()
        conn_worker.close()


if __name__ == "__main__":
    unittest.main()
