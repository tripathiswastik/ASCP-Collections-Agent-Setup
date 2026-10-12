"""Unit tests for the Oracle Lock Diagnostics Engine."""

import unittest
from ascp_agent.lock_engine import LockDiagnosticsEngine, LOCK_MODE_MAPPING

class TestLockDiagnosticsEngine(unittest.TestCase):
    def setUp(self):
        self.engine = LockDiagnosticsEngine(simulated_scenario="ora_00054_mode6")

    def test_lock_mode_mappings(self):
        self.assertEqual(LOCK_MODE_MAPPING[6][0], "Exclusive (X)")
        self.assertEqual(LOCK_MODE_MAPPING[3][0], "ROW_X (SX)")
        self.assertEqual(LOCK_MODE_MAPPING[0][0], "NONE")

    def test_hierarchical_lock_query_execution(self):
        telemetry = self.engine.execute_hierarchical_lock_query()
        self.assertGreater(len(telemetry), 0)
        root = self.engine.isolate_root_blocker(telemetry)
        self.assertIsNotNone(root)
        self.assertEqual(root["sid"], 412)
        self.assertEqual(root["lock_depth"], 1)
        self.assertEqual(root["locked_mode"], 6)
        self.assertEqual(root["object_name"], "MSC_ST_DEMANDS")

    def test_blocked_workers_telemetry(self):
        telemetry = self.engine.execute_hierarchical_lock_query()
        workers = [t for t in telemetry if t["lock_depth"] > 1]
        self.assertEqual(len(workers), 2)
        for w in workers:
            self.assertEqual(w["blocking_session"], 412)
            self.assertEqual(w["locked_mode"], 0)

if __name__ == "__main__":
    unittest.main()
