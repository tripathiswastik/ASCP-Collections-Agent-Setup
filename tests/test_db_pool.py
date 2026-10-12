"""
Python Version: 3.10+ (Target: Python 3.10, 3.11, 3.12)
Purpose: Unit tests for OracleConnectionPool and query execution with simulation fallback.
Runs-in: Local development shell, CI test runner, or autonomous agent evaluation runtime.
"""

import unittest
from unittest.mock import MagicMock, patch

from ascp_agent.config import OracleConfig
from ascp_agent.db import OracleConnectionPool, QueryResult, get_oracle_pool


class TestOracleConnectionPool(unittest.TestCase):
    """Test suite validating connection pool initialization, execution, and simulation fallback."""

    def setUp(self):
        self.sim_config = OracleConfig(
            host="localhost",
            port=1521,
            service_name="TESTDB",
            username="TEST_USER",
            password="password",
            use_simulation=True
        )
        self.pool = OracleConnectionPool(self.sim_config)

    def test_simulation_fallback_mode_flag(self):
        """Validates that pool identifies simulation mode accurately."""
        self.assertTrue(self.pool.is_simulation)
        ping_status = self.pool.ping()
        self.assertTrue(ping_status["alive"])
        self.assertEqual(ping_status["mode"], "SIMULATION")

    def test_query_result_to_dicts_conversion(self):
        """Validates QueryResult column-to-dict lowercase mapping."""
        res = QueryResult(
            columns=["SID", "SERIAL#", "LOCKED_MODE"],
            rows=[(142, 2891, 6), (88, 1140, 6)],
            row_count=2,
            execution_time_ms=1.2,
            is_simulated=False
        )
        dicts = res.to_dicts()
        self.assertEqual(len(dicts), 2)
        self.assertEqual(dicts[0]["sid"], 142)
        self.assertEqual(dicts[0]["serial#"], 2891)
        self.assertEqual(dicts[0]["locked_mode"], 6)

    def test_simulation_query_execution(self):
        """Validates that execute_query returns structured simulation fallback without throwing."""
        res = self.pool.execute_query("SELECT * FROM V$SESSION")
        self.assertTrue(res.is_simulated)
        self.assertGreater(res.row_count, 0)
        self.assertIn("STATUS", res.columns)

    def test_async_simulation_query_execution(self):
        """Validates async query execution in simulation mode."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(self.pool.execute_query_async("SELECT * FROM V$LOCK"))
            self.assertTrue(res.is_simulated)
            self.assertEqual(res.columns, ["STATUS", "MESSAGE"])
        finally:
            loop.close()

    def test_singleton_get_oracle_pool(self):
        """Validates get_oracle_pool singleton returns consistent pool instance."""
        p1 = get_oracle_pool()
        p2 = get_oracle_pool()
        self.assertIs(p1, p2)


if __name__ == "__main__":
    unittest.main()
