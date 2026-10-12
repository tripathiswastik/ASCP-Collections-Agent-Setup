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

    def test_async_hierarchical_lock_query(self):
        import asyncio
        telemetry = asyncio.run(self.engine.execute_hierarchical_lock_query_async())
        self.assertGreater(len(telemetry), 0)
        root = self.engine.isolate_root_blocker(telemetry)
        self.assertIsNotNone(root)
        self.assertEqual(root["sid"], 412)
        self.assertEqual(root["locked_mode"], 6)

    def test_automated_registry_lock_reset(self):
        from ascp_agent.pipeline_monitor import PipelineMonitor
        from ascp_agent.remediation import RemediationEngine
        monitor = PipelineMonitor(simulated_scenario="stage2_stalled")
        res = monitor.verify_and_reset_registry(instance_id=1001)
        self.assertTrue(res["reset_required"])
        self.assertEqual(res["normalized_st_status"], 0)
        self.assertEqual(res["parameters"]["Validation"], "No")

        rem = RemediationEngine()
        purge_res = rem.execute_purge_staging_no_validation(instance_id=1001)
        self.assertTrue(purge_res.success)
        self.assertEqual(purge_res.audit_record["normalized_st_status"], 0)

if __name__ == "__main__":
    unittest.main()
