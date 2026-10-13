"""Property-Style and Adversarial Input Validation Tests.
Validates boundary values, type safety, and SQL injection sanitization on:
1. _require_int (numeric bounds, boolean rejection, non-int rejection)
2. _require_identifier (Oracle naming syntax, SQL injection payload rejection)
3. _validated_mode (snapshot refresh modes)
"""

from __future__ import annotations

import unittest

from ascp_agent.remediation import _require_identifier, _require_int, _validated_mode


class TestPropertyValidation(unittest.TestCase):

    # =========================================================================
    # 1. _require_int Property Tests
    # =========================================================================

    def test_require_int_valid_values(self):
        valid_cases = [1, 42, 1001, 28419, 999999, 1000000]
        for val in valid_cases:
            self.assertEqual(_require_int(val, "sid"), val)

    def test_require_int_rejects_booleans(self):
        """Python bool subclasses int; booleans must be strictly rejected."""
        with self.assertRaises(ValueError):
            _require_int(True, "sid")
        with self.assertRaises(ValueError):
            _require_int(False, "serial")

    def test_require_int_rejects_zero_and_negatives(self):
        with self.assertRaises(ValueError):
            _require_int(0, "sid")
        with self.assertRaises(ValueError):
            _require_int(-1, "serial")
        with self.assertRaises(ValueError):
            _require_int(-9999, "instance_id")

    def test_require_int_rejects_floats_and_strings(self):
        with self.assertRaises(ValueError):
            _require_int(12.34, "sid")
        with self.assertRaises(ValueError):
            _require_int("412", "sid")
        with self.assertRaises(ValueError):
            _require_int("1; DROP TABLE users; --", "sid")

    def test_require_int_session_limits(self):
        # SID maximum Oracle session limit is 1,000,000
        with self.assertRaises(ValueError):
            _require_int(1_000_001, "sid")
        # Other fields can be larger (e.g. concurrent request ID)
        self.assertEqual(_require_int(1_000_001, "request_id"), 1_000_001)

    # =========================================================================
    # 2. _require_identifier Property Tests
    # =========================================================================

    def test_require_identifier_valid_names(self):
        valid_identifiers = [
            "MSC_ST_DEMANDS",
            "msc_demands",
            "MLOG$_OE_ORDER_LINES",
            "MSC_CL_COLLECTION",
            "SCHEMA.TABLE_NAME",
            "MSC_PIPE_PRD1#",
            "A$B_C"
        ]
        for name in valid_identifiers:
            clean = _require_identifier(name, "table_name")
            self.assertEqual(clean, name.upper().strip())

    def test_require_identifier_rejects_sql_injection_payloads(self):
        adversarial_payloads = [
            "MSC_DEMANDS; DROP TABLE MSC_DEMANDS; --",
            "MSC_DEMANDS' OR '1'='1",
            "MSC_DEMANDS/**/UNION/**/SELECT",
            "SYS.DUAL; EXEC DBMS_PIPE.PURGE('X');",
            "TABLE_NAME\nDROP TABLE X",
            "TABLE_NAME\rDROP TABLE X",
            "TABLE_NAME\x00DROP",
            "TAB--comment",
            "TAB/*inline*/",
            "123_INVALID_START",
            "",
            "   ",
            ";",
            "MSC_DEMANDS`",
            "MSC_DEMANDS\""
        ]
        for payload in adversarial_payloads:
            with self.assertRaises(ValueError, msg=f"Payload was not rejected: {payload!r}"):
                _require_identifier(payload, "table_name")

    def test_require_identifier_rejects_excessive_length(self):
        long_name = "A" * 65
        with self.assertRaises(ValueError):
            _require_identifier(long_name, "identifier")

    # =========================================================================
    # 3. _validated_mode Property Tests
    # =========================================================================

    def test_validated_mode_valid(self):
        self.assertEqual(_validated_mode("F"), "F")
        self.assertEqual(_validated_mode("f"), "F")
        self.assertEqual(_validated_mode("C"), "C")
        self.assertEqual(_validated_mode("c"), "C")

    def test_validated_mode_invalid_rejects(self):
        invalid_modes = ["FAST", "COMPLETE", "X", "f; DROP TABLE y;", "", None, 1, False]
        for mode in invalid_modes:
            with self.assertRaises(ValueError, msg=f"Mode was not rejected: {mode!r}"):
                _validated_mode(mode)


if __name__ == "__main__":
    unittest.main()
