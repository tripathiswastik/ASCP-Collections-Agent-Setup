"""Unit tests for State Machine, Database Lock Engine, and ITSM Orchestration Edge Cases.
Verifies:
1. State loss prevention via explicit list field reducers.
2. interrupt() isolation, re-execution safety, and control-flow exception signal preservation.
3. Undo volume threshold (>50,000 records) rollback safety and automated ServiceNow P1 escalation.
4. Crashed pipeline registry recovery (ST_STATUS reset + staging purge with Validation=No).
5. Self-healing schema validation loop handling markdown code fences and reprompting.
6. ServiceNow 30-minute OAuth token caching and HTTP 429 rate limiting with Retry-After.
"""

from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ascp_agent.itsm_service_now import ServiceNowClient
from ascp_agent.lock_engine import LockDiagnosticsEngine
from ascp_agent.remediation import RemediationEngine
from ascp_agent.schema_validator import DiagnosticReport, validate_schema_node
from ascp_agent.state import (
    DiagnosticState,
    GraphInterrupt,
    InterruptSignal,
    Overwrite,
    interrupt,
)


class TestOrchestrationEdgeCases(unittest.TestCase):

    def test_state_list_fields_concatenation_reducers(self):
        """Verify that all list fields preserve prior state across super-steps via reducers."""
        state = DiagnosticState()
        self.assertEqual(state["evidence_bundle"], [])
        self.assertEqual(state["ranked_hypotheses"], [])
        self.assertEqual(state["missing_evidence"], [])
        self.assertEqual(state["remediation_blockers"], [])

        # Super-step 1: add initial items
        state.apply_update({
            "evidence_bundle": [{"id": "ev1", "text": "ORA-00054 on MSC_ST_DEMANDS"}],
            "ranked_hypotheses": [{"domain": "DATABASE_LOCK", "score": 0.95}],
            "missing_evidence": ["need v$transaction"],
            "remediation_blockers": ["worker_active"],
            "detected_errors": ["ORA-00054"],
        })
        self.assertEqual(len(state["evidence_bundle"]), 1)
        self.assertEqual(len(state["ranked_hypotheses"]), 1)
        self.assertEqual(state["missing_evidence"], ["need v$transaction"])

        # Super-step 2: append additional items without overwriting
        state.apply_update({
            "evidence_bundle": [{"id": "ev2", "text": "Root blocker SID 412"}],
            "ranked_hypotheses": [{"domain": "ORCHESTRATION_REGISTRY", "score": 0.10}],
            "missing_evidence": ["need undo volume"],
            "remediation_blockers": ["high_rollback_risk"],
            "detected_errors": ["ORA-00060"],
        })
        self.assertEqual(len(state["evidence_bundle"]), 2)
        self.assertEqual(state["evidence_bundle"][0]["id"], "ev1")
        self.assertEqual(state["evidence_bundle"][1]["id"], "ev2")
        self.assertEqual(len(state["ranked_hypotheses"]), 2)
        self.assertEqual(state["missing_evidence"], ["need v$transaction", "need undo volume"])
        self.assertEqual(state["remediation_blockers"], ["worker_active", "high_rollback_risk"])
        self.assertEqual(state["detected_errors"], ["ORA-00054", "ORA-00060"])

        # Explicit Overwrite clears accumulated list when intended
        state.apply_update({
            "missing_evidence": Overwrite(["all_cleared"]),
        })
        self.assertEqual(state["missing_evidence"], ["all_cleared"])

    def test_interrupt_signal_inherits_base_exception_not_swallowed_by_exception(self):
        """Verify that InterruptSignal and GraphInterrupt are not caught by broad except Exception."""
        # Standard Exception catch block
        swallowed = False
        try:
            try:
                interrupt({"test": "pause"})
            except Exception:  # noqa: BLE001
                swallowed = True
        except InterruptSignal as sig:
            self.assertEqual(sig.payload, {"test": "pause"})

        self.assertFalse(swallowed, "InterruptSignal was mistakenly caught by 'except Exception:'!")
        self.assertTrue(issubclass(GraphInterrupt, BaseException))

    def test_undo_volume_threshold_triggers_servicenow_p1_alert(self):
        """Verify that undo record volume > 50,000 defers session kill and dispatches ServiceNow P1."""
        engine = RemediationEngine()
        lock_eng = LockDiagnosticsEngine()

        # Low volume (420 records) -> proceed
        low_undo = lock_eng.inspect_session_undo_volume(412)
        self.assertFalse(low_undo["high_rollback_risk"])
        self.assertEqual(low_undo["recommendation"], "PROCEED_WITH_TERMINATION")

        # High volume (150,000 records) -> high risk
        high_undo = lock_eng.inspect_session_undo_volume(999)
        self.assertTrue(high_undo["high_rollback_risk"])
        self.assertGreater(high_undo["used_urec"], 50000)
        self.assertEqual(high_undo["recommendation"], "DEFER_KILL_ALERT_DBA")

        # Execute kill with high undo volume
        res = engine.execute_kill_session(
            sid=999,
            serial=12345,
            object_name="MSC_ST_DEMANDS",
            undo_check=high_undo,
            dry_run=False,
        )
        self.assertFalse(res.success)
        self.assertEqual(res.action, "DEFERRED_ROLLBACK_ALERT")
        self.assertIn("DEFERRED", res.command_executed)
        self.assertIn("ServiceNow", res.message)
        self.assertIsNotNone(res.audit_record.get("servicenow_incident"))
        incident = res.audit_record["servicenow_incident"]
        self.assertTrue(incident.get("status") in ("CREATED", "SIMULATED_DISPATCH", "UPDATED_EXISTING"))

    def test_crashed_pipeline_registry_recovery_subroutine(self):
        """Verify crashed pipeline recovery validates active workers before resetting ST_STATUS."""
        engine = RemediationEngine()

        # 1. Blocked when active workers > 0
        blocked_res = engine.recover_crashed_pipeline_registry(
            instance_id=1001,
            instance_code="PRD1",
            dry_run=False,
            active_workers_count=2,
        )
        self.assertFalse(blocked_res.success)
        self.assertEqual(blocked_res.action, "RECOVERY_BLOCKED_ACTIVE_WORKERS")
        self.assertIn("still active", blocked_res.message)

        # 2. Succeeds when active workers == 0
        success_res = engine.recover_crashed_pipeline_registry(
            instance_id=1001,
            instance_code="PRD1",
            dry_run=False,
            active_workers_count=0,
        )
        self.assertTrue(success_res.success)
        self.assertEqual(success_res.action, "RECOVER_CRASHED_PIPELINE")
        self.assertIn("ST_STATUS = 0", success_res.command_executed)
        self.assertIn("PURGE_STAGING_TABLES_SUB", success_res.command_executed)
        self.assertIn("p_validation => 'N'", success_res.command_executed)

    def test_schema_validator_handles_markdown_code_fences_and_self_heals(self):
        """Verify DiagnosticReport parses JSON wrapped in markdown fences and provides error reprompt tracebacks."""
        valid_json = {
            "diagnostic_summary": {
                "failing_stage": "ODS_LOAD",
                "failing_program_short_name": "MSCPDCW",
                "request_id": 890415,
                "primary_error_code": "ORA-00054",
                "confidence_score": 0.965,
            },
            "root_cause_analysis": {
                "summary": "Exclusive TM Mode 6 lock held on MSC_ST_DEMANDS.",
                "affected_objects": ["MSC_ST_DEMANDS"],
                "is_infrastructure_issue": False,
                "is_data_validation_issue": False,
            },
            "remediation_plan": {
                "immediate_action_required": "KILL_SESSION",
                "sql_scripts_to_execute": ["ALTER SYSTEM KILL SESSION '412,28419' IMMEDIATE;"],
                "os_commands_to_execute": [],
                "profile_option_adjustments": [],
                "requires_manager_bounce": False,
            },
        }

        # Case 1: Plain JSON
        rep1 = DiagnosticReport.model_validate_json(json.dumps(valid_json))
        self.assertEqual(rep1.diagnostic_summary.primary_error_code, "ORA-00054")

        # Case 2: JSON wrapped in ```json ... ``` code fence with preamble and postamble
        fenced = f"Here is the autonomous diagnosis:\n```json\n{json.dumps(valid_json, indent=2)}\n```\nPlease review and execute."
        rep2 = DiagnosticReport.model_validate_json(fenced)
        self.assertEqual(rep2.diagnostic_summary.primary_error_code, "ORA-00054")
        self.assertEqual(rep2.remediation_plan.immediate_action_required, "KILL_SESSION")

        # Case 3: Invalid JSON output generates reprompt feedback in validate_schema_node
        invalid_state = {"raw_llm_output": "Not a valid json response", "retry_count": 0}
        out = validate_schema_node(invalid_state)
        self.assertFalse(out["is_validated"])
        self.assertEqual(out["retry_count"], 1)
        self.assertIn("reprompt_traceback", out)
        self.assertIn("JSONDecodeError", out["validation_error"])

    def test_servicenow_oauth_caching_and_refresh(self):
        """Verify ServiceNow OAuth tokens are cached for 30 minutes and refreshed upon expiry."""
        client = ServiceNowClient()
        token1 = client.get_valid_oauth_token()
        self.assertTrue(token1.startswith("tok_sn_"))

        # Re-request within 30 minutes returns the exact same cached token
        token2 = client.get_valid_oauth_token()
        self.assertEqual(token1, token2)

        # Force refresh yields a new token
        token3 = client.get_valid_oauth_token(force_refresh=True)
        self.assertNotEqual(token1, token3)

        # Artificially expire the token
        client._token_expires_at = time.time() - 10
        token4 = client.get_valid_oauth_token()
        self.assertNotEqual(token3, token4)

    def test_servicenow_rate_limit_backoff_and_retry_after(self):
        """Verify ServiceNow dispatch handles HTTP 429 with exponential backoff and Retry-After header."""
        client = ServiceNowClient()
        client.config.dry_run = False
        client.config.instance_url = "https://mock-sn.example.com"
        client.config.password = "secret"

        mock_session = MagicMock()
        mock_429 = MagicMock()
        mock_429.status_code = 429
        mock_429.headers = {"Retry-After": "0"}

        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.json.return_value = {"result": {"number": "INC009988", "sys_id": "sys_abc123"}}

        # Returns 429 first, then 200
        mock_session.post.side_effect = [mock_429, mock_200]
        client._session = mock_session

        payload = {"short_description": "Test 429 Retry", "description": "Testing rate limit handling"}
        res = client.dispatch_incident(payload, max_retries=3)

        self.assertEqual(res["status"], "CREATED")
        self.assertEqual(res["incident_number"], "INC009988")
        self.assertEqual(mock_session.post.call_count, 2)


if __name__ == "__main__":
    unittest.main()
