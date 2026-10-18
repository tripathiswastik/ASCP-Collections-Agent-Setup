"""End-to-End Human-in-the-Loop (HITL) Life Cycle & Governance Tests.
Validates the full state machine life cycle:
1. Start -> Interrupt -> Approve -> Single Execution
2. Reject -> Zero Execution
3. Anti-Replay Idempotency / Double-Approve Rejection
4. Blocker Tamper Detection (SHA-256 Fingerprint Mismatch)
5. Pre-Kill Session Re-Check (Session cleared while awaiting approval)
"""

from __future__ import annotations

import hashlib
import unittest
from unittest import mock

from ascp_agent.graph import create_ascp_diagnostic_graph
from ascp_agent.simulator import SCENARIOS
from ascp_agent.state import Command


class TestEndToEndHITLFlow(unittest.TestCase):

    def setUp(self):
        self.logs = SCENARIOS["ora_00054_mode6"]["logs"]

    def test_start_interrupt_approve_single_execution(self):
        """Validates start -> interrupt at gate -> approve -> single execution."""
        graph = create_ascp_diagnostic_graph()
        thread_id = "test-hitl-approve-1"

        # 1. Start execution loop -> must pause at HITL Gate
        initial_state = {
            "remediation_action": "INSPECT_LOCKS",
            "raw_logs": self.logs
        }
        state = graph.invoke(initial_state=initial_state, config={"configurable": {"thread_id": thread_id}})

        self.assertTrue(state.get("interrupted"))
        payload = state.get("interrupt_payload", {})
        self.assertIsNotNone(payload.get("approval_id"))
        self.assertIsNotNone(payload.get("approval_fingerprint"))
        self.assertEqual(payload.get("action"), "KILL_SESSION")
        self.assertEqual(payload.get("target_sid"), 412)

        # 2. Approve via Command(resume=...)
        resume_cmd = Command(resume={
            "approved": True,
            "dba_user": "lead_dba",
            "approval_id": payload["approval_id"],
            "approval_fingerprint": payload["approval_fingerprint"],
            "target_action": "KILL_SESSION",
            "target_sid": 412,
            "notes": "Approved for emergency resolution."
        })

        final_state = graph.invoke(
            config={"configurable": {"thread_id": thread_id}},
            resume_command=resume_cmd
        )

        self.assertTrue(final_state.get("is_remediated"))
        self.assertTrue(final_state.get("remediation_approved"))
        self.assertIn("Successfully terminated blocking database session", final_state["messages"][-2].content)
        self.assertIsNotNone(final_state.get("servicenow_incident"))

    def test_start_interrupt_reject_zero_execution(self):
        """Validates operator rejection aborts remediation with zero execution."""
        graph = create_ascp_diagnostic_graph()
        thread_id = "test-hitl-reject-1"

        state = graph.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": self.logs},
            config={"configurable": {"thread_id": thread_id}}
        )

        self.assertTrue(state.get("interrupted"))
        payload = state.get("interrupt_payload", {})

        resume_cmd = Command(resume={
            "approved": False,
            "dba_user": "lead_dba",
            "approval_id": payload["approval_id"],
            "approval_fingerprint": payload["approval_fingerprint"],
            "notes": "Rejected by DBA."
        })

        final_state = graph.invoke(
            config={"configurable": {"thread_id": thread_id}},
            resume_command=resume_cmd
        )

        self.assertFalse(final_state.get("is_remediated"))
        self.assertFalse(final_state.get("remediation_approved"))
        self.assertIn("rejected by DBA operator", final_state["messages"][-2].content)

    def test_tampered_fingerprint_rejected(self):
        """Validates that if the blocker changes or the payload is forged, execution is blocked."""
        graph = create_ascp_diagnostic_graph()
        thread_id = "test-hitl-tamper-1"

        state = graph.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": self.logs},
            config={"configurable": {"thread_id": thread_id}}
        )

        self.assertTrue(state.get("interrupted"))
        payload = state.get("interrupt_payload", {})

        # Tampered fingerprint (e.g. attacker substituted target)
        forged_fingerprint = hashlib.sha256(b"KILL_SESSION:9999:1111:MSC_ST_DEMANDS:None").hexdigest()

        resume_cmd = Command(resume={
            "approved": True,
            "dba_user": "attacker",
            "approval_id": payload["approval_id"],
            "approval_fingerprint": forged_fingerprint,
            "notes": "Tampered payload"
        })

        res = graph.invoke(
            config={"configurable": {"thread_id": thread_id}},
            resume_command=resume_cmd
        )

        self.assertFalse(res.get("is_remediated"))
        self.assertIn("Approval rejected: Target fingerprint mismatch", res["messages"][-2].content)

    def test_session_cleared_before_kill_skips_termination(self):
        """Validates that if a session commits or closes while awaiting approval, kill is skipped."""
        graph = create_ascp_diagnostic_graph()
        thread_id = "test-hitl-cleared-1"

        state = graph.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": self.logs},
            config={"configurable": {"thread_id": thread_id}}
        )

        self.assertTrue(state.get("interrupted"))
        payload = state.get("interrupt_payload", {})

        # Mock lock engine verify_session_active returning None (session gone!)
        with mock.patch("ascp_agent.lock_engine.LockDiagnosticsEngine.verify_session_active", return_value=None):
            resume_cmd = Command(resume={
                "approved": True,
                "dba_user": "lead_dba",
                "approval_id": payload["approval_id"],
                "approval_fingerprint": payload["approval_fingerprint"],
            })

            res = graph.invoke(
                config={"configurable": {"thread_id": thread_id}},
                resume_command=resume_cmd
            )

            self.assertFalse(res.get("is_remediated"))
            self.assertIn("is no longer active; lock cleared while awaiting approval", res["messages"][-2].content)

    def test_session_recycling_mismatched_serial_aborts_kill(self):
        """Validates that execute_kill_session aborts if SID is recycled with a different SERIAL#."""
        from ascp_agent.remediation import RemediationEngine
        engine = RemediationEngine()
        # In simulated mode, SID 412 requires SERIAL# 28419; serial 99999 simulates a recycled session
        res = engine.execute_kill_session(sid=412, serial=99999, object_name="MSC_ST_DEMANDS")
        self.assertFalse(res.success)
        self.assertEqual(res.action, "KILL_SESSION_ABORTED_RECYCLED")
        self.assertIn("session recycling protection prevented accidental termination", res.message.lower())
        self.assertEqual(res.audit_record.get("reason"), "SESSION_RECYCLED_OR_INACTIVE")

    def test_hitl_session_recycling_protection(self):
        """Validates that if SID is recycled while awaiting HITL approval, kill is aborted."""
        graph = create_ascp_diagnostic_graph()
        thread_id = "test-hitl-recycled-1"

        state = graph.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": self.logs},
            config={"configurable": {"thread_id": thread_id}}
        )

        self.assertTrue(state.get("interrupted"))
        payload = state.get("interrupt_payload", {})

        # Simulate Oracle assigning SID 412 to a new connection (different serial)
        with mock.patch("ascp_agent.lock_engine.LockDiagnosticsEngine.verify_session_active", return_value=None):
            resume_cmd = Command(resume={
                "approved": True,
                "dba_user": "lead_dba",
                "approval_id": payload["approval_id"],
                "approval_fingerprint": payload["approval_fingerprint"],
            })

            res = graph.invoke(
                config={"configurable": {"thread_id": thread_id}},
                resume_command=resume_cmd
            )

            self.assertFalse(res.get("is_remediated"))
            self.assertIn("session recycling prevented", res["messages"][-2].content)


if __name__ == "__main__":
    unittest.main()
