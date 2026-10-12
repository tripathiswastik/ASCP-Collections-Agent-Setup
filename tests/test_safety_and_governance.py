"""
Unit tests for enterprise safety, SQL injection protection, fail-closed configuration,
and human-in-the-loop governance guardrails.
"""

import unittest
from ascp_agent.config import OracleConfig, ServiceNowConfig
from ascp_agent.remediation import (
    RemediationEngine,
    validate_oracle_identifier,
    validate_session_numeric,
    format_kill_session_sql,
    format_align_indexes_sql
)
from ascp_agent.drain_parser import DrainLogParser


class TestSafetyAndGovernance(unittest.TestCase):
    """Validates negative test cases, SQL injection prevention, and fail-closed configurations."""

    def test_oracle_config_fail_closed_without_password(self):
        """Validates that production Oracle connection fails closed when password is unset."""
        cfg = OracleConfig(use_simulation=False, password="", host="prod-db.corp.com")
        with self.assertRaises(ValueError) as ctx:
            cfg.validate()
        self.assertIn("ORACLE_PASSWORD is empty or unset", str(ctx.exception))

    def test_oracle_config_fail_closed_with_mock_host(self):
        """Validates that production Oracle connection fails closed when mock host is specified."""
        cfg = OracleConfig(use_simulation=False, password="RealPassword123!", host="ebs-db.corp.internal")
        with self.assertRaises(ValueError) as ctx:
            cfg.validate()
        self.assertIn("default mock endpoint", str(ctx.exception))

    def test_servicenow_config_fail_closed_without_password(self):
        """Validates that production ServiceNow integration fails closed when password is unset."""
        cfg = ServiceNowConfig(enabled=True, dry_run=False, password="")
        with self.assertRaises(ValueError) as ctx:
            cfg.validate()
        self.assertIn("SN_PASSWORD is empty or unset", str(ctx.exception))

    def test_oracle_identifier_sql_injection_rejection(self):
        """Validates that SQL injection payloads in table or procedure names are strictly rejected."""
        malicious_identifiers = [
            "MSC_DEMANDS; DROP TABLE MSC_DEMANDS--",
            "MSC_ST_DEMANDS' OR '1'='1",
            "table name with spaces",
            "EXEC xp_cmdshell('dir')",
            "MSC_ST_DEMANDS/*comment*/",
            ""
        ]
        for bad_id in malicious_identifiers:
            with self.assertRaises(ValueError, msg=f"Should reject: {bad_id}"):
                validate_oracle_identifier(bad_id, "table_name")

    def test_oracle_identifier_valid_patterns(self):
        """Validates that legal Oracle identifiers (including $, #, and underscores) are accepted."""
        valid_identifiers = [
            "MSC_ST_DEMANDS",
            "V$SESSION",
            "MLOG$_OE_ORDER_LINES",
            "SYS_C00123#",
            "MSC_APPS_INSTANCES"
        ]
        for good_id in valid_identifiers:
            cleaned = validate_oracle_identifier(good_id)
            self.assertEqual(cleaned, good_id)

    def test_session_numeric_validation(self):
        """Validates that session ID and serial must be positive integers within bounds."""
        with self.assertRaises(ValueError):
            validate_session_numeric(-1, "sid")
        with self.assertRaises(ValueError):
            validate_session_numeric(0, "sid")
        with self.assertRaises(ValueError):
            validate_session_numeric("not_a_number", "sid")
        with self.assertRaises(ValueError):
            validate_session_numeric(99_999_999, "sid")  # Exceeds max Oracle SID

        self.assertEqual(validate_session_numeric(412, "sid"), 412)
        self.assertEqual(validate_session_numeric("28419", "serial"), 28419)

    def test_format_kill_session_rejects_injection(self):
        """Validates that format_kill_session_sql strictly rejects non-numeric SID or serial."""
        with self.assertRaises(ValueError):
            format_kill_session_sql("412' OR '1'='1", 28419)

    def test_format_align_indexes_rejects_injection(self):
        """Validates that format_align_indexes_sql strictly rejects SQL injection."""
        with self.assertRaises(ValueError):
            format_align_indexes_sql("MSC_DEMANDS'; DROP TABLE APPS.FND_USER;--")

    def test_kill_session_deferred_on_high_rollback_volume(self):
        """Validates that session termination is deferred when PMON rollback volume is high (SID 999)."""
        engine = RemediationEngine()
        # SID 999 in inspect_session_undo_volume simulates 150,000 uncommitted records (> 100,000 threshold)
        res = engine.execute_kill_session(sid=999, serial=10101, object_name="MSC_ST_DEMANDS")
        self.assertFalse(res.success)
        self.assertEqual(res.action, "DEFERRED_ROLLBACK_ALERT")
        self.assertIn("Session termination deferred", res.message)
        self.assertIn("High Undo Rollback Volume", res.command_executed)

    def test_kill_session_dry_run_flag(self):
        """Validates that dry-run mode returns validated statement without mutating state."""
        engine = RemediationEngine()
        res = engine.execute_kill_session(sid=412, serial=28419, object_name="MSC_ST_DEMANDS", dry_run=True)
        self.assertTrue(res.success)
        self.assertTrue(res.dry_run)
        self.assertEqual(res.action, "KILL_SESSION_DRY_RUN")
        self.assertTrue(res.command_executed.startswith("-- DRY-RUN:"))

    def test_drain_parser_resilience_to_adversarial_input(self):
        """Validates that DrainLogParser gracefully handles empty, malformed, or excessively long lines."""
        parser = DrainLogParser()
        # 1. Empty input
        self.assertEqual(parser.parse_log_text(""), [])

        # 2. Adversarially long log line (20,000 characters)
        huge_line = "ORA-00054: resource busy " + ("A" * 20000)
        results = parser.parse_log_text(huge_line)
        self.assertIsInstance(results, list)
        self.assertGreaterEqual(len(results), 1)

        # 3. Only whitespace and special symbols
        weird_input = "\n\n   \t  \n---\n***\n"
        results2 = parser.parse_log_text(weird_input)
        self.assertIsInstance(results2, list)


if __name__ == "__main__":
    unittest.main()
