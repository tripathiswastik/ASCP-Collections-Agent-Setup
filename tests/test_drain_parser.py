"""Unit tests for the Drain Log Parsing Engine."""

from __future__ import annotations

import unittest

from ascp_agent.drain_parser import DrainLogParser


class TestDrainLogParser(unittest.TestCase):
    def setUp(self):
        self.parser = DrainLogParser(depth=4, similarity_threshold=0.5)

    def test_single_line_parsing(self):
        line = "[12-OCT-2025 04:12:01]: Cause: ORA-00054: resource busy acquire with NOWAIT specified on table MSC_ST_DEMANDS."
        res = self.parser.parse_line(line)
        self.assertIn("Cause: ORA-00054: resource busy acquire with NOWAIT specified on table", res["template"])
        self.assertEqual(res["parameters"]["TIMESTAMP"], "12-OCT-2025 04:12:01")
        self.assertIn("MSC_ST_DEMANDS", res["parameters"]["TARGET_OBJECTS"])

    def test_clustering_similar_logs(self):
        line1 = "[12-OCT-2025 04:12:01]: Worker 1 failed on table MSC_ST_DEMANDS."
        line2 = "[12-OCT-2025 04:12:05]: Worker 2 failed on table MSC_ST_SUPPLIES."
        res1 = self.parser.parse_line(line1)
        res2 = self.parser.parse_line(line2)
        # Should be assigned into same cluster
        self.assertEqual(res1["cluster_id"], res2["cluster_id"])
        self.assertIn("<TARGET_OBJECT>", res2["template"])

    def test_multi_line_log_dump(self):
        log_dump = """
        [12-OCT-2025 05:01:22]: Beginning global surrogate key resolution.
        [12-OCT-2025 05:01:45]: ORA-00001: unique constraint violated.
        [12-OCT-2025 05:01:50]: Error in package MSC_CL_COLLECTION.LOAD_DEMANDS.
        """
        results = self.parser.parse_log_text(log_dump)
        self.assertEqual(len(results), 3)

    def test_thread_and_memory_masking_preserving_ora_codes(self):
        line = "[12-OCT-2025 04:12:01]: tid=4812 Thread-9 crashed at 0x7fff89ab10cd with ORA-00054: resource busy."
        res = self.parser.parse_line(line)
        self.assertIn("ORA-00054:", res["template"])
        self.assertIn("<THREAD_ID>", res["template"])
        self.assertIn("<MEM_ADDR>", res["template"])
        self.assertIn("0x7fff89ab10cd", res["parameters"]["MEM_ADDRESSES"])

if __name__ == "__main__":
    unittest.main()
