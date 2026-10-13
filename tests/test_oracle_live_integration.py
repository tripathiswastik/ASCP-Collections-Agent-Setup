"""Live Oracle Integration Test using Oracle Free Container (gvenzl/oracle-free).
Reproduces real ORA-00054 (resource busy and acquire with NOWAIT specified)
between two concurrent live database sessions, triggers LockDiagnosticsEngine
against dynamic V$ views, and asserts the root blocker is accurately isolated.
"""

import os
import sys
import time
import unittest
from typing import Optional, Dict, Any

# Add workspace root to sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ascp_agent.config import OracleConfig
from ascp_agent.lock_engine import LockDiagnosticsEngine, OracleConnectionPool


def get_live_oracle_config() -> Optional[OracleConfig]:
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
        pool_increment=1
    )


def is_oracle_live_available() -> bool:
    """Probes if a live Oracle database is reachable."""
    try:
        import oracledb
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
    except Exception:
        return False


class TestOracleLiveIntegration(unittest.TestCase):
    """End-to-end integration test validating Lock Engine against live Oracle instance."""

    @classmethod
    def setUpClass(cls):
        if not is_oracle_live_available():
            raise unittest.SkipTest("Live Oracle database not accessible (skip for non-container CI runs)")

        cls.config = get_live_oracle_config()
        import oracledb
        cls.oracledb = oracledb

        # Setup dedicated test table
        with cls.oracledb.connect(
            user=cls.config.username,
            password=cls.config.password,
            host=cls.config.host,
            port=cls.config.port,
            service_name=cls.config.service_name
        ) as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute("DROP TABLE TEST_MSC_ST_DEMANDS PURGE")
                except Exception:
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
                ) as conn:
                    with conn.cursor() as cur:
                        cur.execute("DROP TABLE TEST_MSC_ST_DEMANDS PURGE")
                        conn.commit()
            except Exception:
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
        # Acquire blocker SID
        cur_blocker.execute("SELECT SYS_CONTEXT('USERENV', 'SID') FROM DUAL")
        blocker_sid = int(cur_blocker.fetchone()[0])

        # Step 1: Hold uncommitted Mode 6 Exclusive Table Lock
        cur_blocker.execute("LOCK TABLE TEST_MSC_ST_DEMANDS IN EXCLUSIVE MODE")

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

        # Step 3: Run ASCP LockDiagnosticsEngine against the live database
        pool = OracleConnectionPool(self.config)
        engine = LockDiagnosticsEngine(pool=pool, config=self.config)

        # Bypass cache to perform live inspection of V$ views
        telemetry = engine.execute_hierarchical_lock_query(bypass_cache=True)
        root_blocker = engine.isolate_root_blocker(telemetry)

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
