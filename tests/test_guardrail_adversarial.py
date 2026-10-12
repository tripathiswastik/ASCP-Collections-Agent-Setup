"""
Adversarial Security & Guardrails Test Suite
Validates SQL comment evasion, CTE mutations, execution role boundaries,
Referer header bypass prevention, approval binding, anti-replay, and TTL expiration.
Zero external dependency: runs cleanly on unittest or pytest.
"""

import time
import unittest
from ascp_agent.config import GuardrailsConfig
from ascp_agent.guardrails import EnterpriseGuardrails, SecurityViolationError
from ascp_agent.graph import create_ascp_diagnostic_graph
from ascp_agent.state import Command


class TestGuardrailAdversarial(unittest.TestCase):
    """Adversarial security test suite verifying guardrail resilience."""

    def setUp(self):
        self.guardrails = EnterpriseGuardrails(GuardrailsConfig())

    # ==========================================================================
    # 1. SQL Comment Stripping & Injection Evasion
    # ==========================================================================

    def test_sql_comment_benign(self):
        """Benign comments in SELECT statements should pass validation."""
        query = "SELECT /*+ INDEX(s IDX_V_SESS) */ sid, serial# FROM v$session WHERE status = 'ACTIVE'"
        self.assertTrue(self.guardrails.validate_sql_command(query))
        self.assertTrue(self.guardrails.validate_diagnostic_query(query))

        multiline = """
        -- Diagnostic query for EBS staging table locks
        SELECT session_id, object_id
        FROM v$locked_object
        /* Filter out temporary segments */
        WHERE object_id > 1000
        """
        self.assertTrue(self.guardrails.validate_sql_command(multiline))
        self.assertTrue(self.guardrails.validate_diagnostic_query(multiline))

    def test_sql_comment_hidden_mutation_rejected(self):
        """Comments attempting to hide mutation tokens or statements must be rejected."""
        # Semicolon hidden with comment
        chained = "SELECT 1 FROM dual; -- comment\nDROP TABLE msc_st_demands;"
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_sql_command(chained)
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_diagnostic_query(chained)

        # Mutation verb disguised inside comment-wrapped query
        wrapped_delete = "SELECT /* inline */ 1 FROM (DELETE FROM msc_st_demands)"
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_sql_command(wrapped_delete)
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_diagnostic_query(wrapped_delete)

    # ==========================================================================
    # 2. CTE Mutation Attacks
    # ==========================================================================

    def test_cte_mutation_rejected(self):
        """Common Table Expressions (WITH ...) containing DML must be blocked."""
        cte_delete = "WITH purged AS (DELETE FROM msc_st_demands RETURNING 1) SELECT * FROM purged"
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_sql_command(cte_delete)
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_diagnostic_query(cte_delete)

        cte_update = "WITH modified AS (UPDATE msc_st_demands SET process_flag = 5) SELECT count(*) FROM modified"
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_sql_command(cte_update)

    def test_cte_read_only_allowed(self):
        """Safe read-only CTE queries must pass validation."""
        cte_safe = "WITH lock_tree AS (SELECT sid, blocking_session FROM v$session WHERE blocking_session IS NOT NULL) SELECT * FROM lock_tree"
        self.assertTrue(self.guardrails.validate_sql_command(cte_safe))
        self.assertTrue(self.guardrails.validate_diagnostic_query(cte_safe))

    # ==========================================================================
    # 3. Execution Boundary & Credential Separation
    # ==========================================================================

    def test_diagnostic_channel_rejects_session_kill(self):
        """ALTER SYSTEM KILL SESSION cannot execute through read-only diagnostic channel."""
        kill_sql = "ALTER SYSTEM KILL SESSION '412,28419' IMMEDIATE"
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_diagnostic_query(kill_sql, execution_role="SELECT_CATALOG_ROLE")

    def test_diagnostic_channel_rejects_privileged_role(self):
        """Diagnostics must strictly use read-only SELECT_CATALOG_ROLE."""
        query = "SELECT * FROM v$session"
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_diagnostic_query(query, execution_role="APPS_REMEDIATE")

    def test_remediation_channel_requires_approval_and_role(self):
        """Remediation execution boundary requires explicit approval, approval ID, and role."""
        kill_sql = "ALTER SYSTEM KILL SESSION '412,28419' IMMEDIATE"

        # Missing HITL approval
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_remediation_command(kill_sql, execution_role="APPS_WRAPPER_EXECUTE", is_hitl_approved=False)

        # Missing approval ID
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_remediation_command(kill_sql, execution_role="APPS_WRAPPER_EXECUTE", is_hitl_approved=True, approval_id=None)

        # Wrong execution role (e.g. attempting to run with read-only credentials)
        with self.assertRaises(SecurityViolationError):
            self.guardrails.validate_remediation_command(kill_sql, execution_role="SELECT_CATALOG_ROLE", is_hitl_approved=True, approval_id="appr-123456")

        # Correct approval and credentials
        self.assertTrue(self.guardrails.validate_remediation_command(
            kill_sql,
            execution_role="APPS_WRAPPER_EXECUTE",
            is_hitl_approved=True,
            approval_id="appr-123456"
        ))

    # ==========================================================================
    # 4. Approval Binding, Anti-Replay, and TTL Expiration
    # ==========================================================================

    def test_graph_approval_ttl_expiration(self):
        """StateGraph resumption must reject expired approvals."""
        graph = create_ascp_diagnostic_graph()
        thread_id = "test-adv-exp"

        state = graph.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": ["ORA-00054 on MSC_ST_DEMANDS"]},
            config={"configurable": {"thread_id": thread_id}}
        )
        self.assertTrue(state.get("interrupted"))
        pending = state.get("interrupt_payload")
        self.assertIsNotNone(pending)
        appr_id = pending.get("approval_id")

        # Tamper with checkpoint expiration timestamp to simulate time travel / expiry
        last_record = graph.checkpointer.get_latest(thread_id)
        last_record.state["interrupt_payload"]["expires_at"] = time.time() - 10  # expired 10s ago

        # Attempt to resume with expired approval
        resume_cmd = Command(resume={
            "approved": True,
            "approval_id": appr_id,
            "dba_user": "TEST_DBA",
            "notes": "Approved late"
        })
        with self.assertRaises(ValueError):
            graph.invoke(config={"configurable": {"thread_id": thread_id}}, resume_command=resume_cmd)

    def test_graph_approval_id_mismatch_rejected(self):
        """StateGraph resumption must reject mismatched approval IDs."""
        graph = create_ascp_diagnostic_graph()
        thread_id = "test-adv-mismatch"

        state = graph.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": ["ORA-00054 on MSC_ST_DEMANDS"]},
            config={"configurable": {"thread_id": thread_id}}
        )
        self.assertTrue(state.get("interrupted"))

        resume_cmd = Command(resume={
            "approved": True,
            "approval_id": "appr-bogus-9999",
            "dba_user": "TEST_DBA",
            "notes": "Forged approval"
        })
        with self.assertRaises(ValueError):
            graph.invoke(config={"configurable": {"thread_id": thread_id}}, resume_command=resume_cmd)

    def test_graph_approval_target_action_mismatch_rejected(self):
        """StateGraph resumption must reject approval for a mismatched remediation action."""
        graph = create_ascp_diagnostic_graph()
        thread_id = "test-adv-act-mismatch"

        state = graph.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": ["ORA-00054 on MSC_ST_DEMANDS"]},
            config={"configurable": {"thread_id": thread_id}}
        )
        self.assertTrue(state.get("interrupted"))
        pending = state.get("interrupt_payload")
        appr_id = pending.get("approval_id")

        resume_cmd = Command(resume={
            "approved": True,
            "approval_id": appr_id,
            "target_action": "PURGE_STAGING",  # Expected KILL_SESSION
            "dba_user": "TEST_DBA"
        })
        with self.assertRaises(ValueError):
            graph.invoke(config={"configurable": {"thread_id": thread_id}}, resume_command=resume_cmd)

    # ==========================================================================
    # 5. Server Authentication & Multi-Session Isolation
    # ==========================================================================

    def test_server_referer_auth_bypass_eliminated(self):
        """Referer header containing localhost:8085 must NOT grant authentication."""
        from web.server import ASCPDiagnosticHandler

        class DummyHandler(ASCPDiagnosticHandler):
            def __init__(self, headers, path="/api/diagnose"):
                self.headers = headers
                self.path = path

        # Case 1: Referer present, no API token -> must be rejected
        h_referer = DummyHandler(headers={"Referer": "http://localhost:8085/index.html"})
        self.assertIsNone(h_referer._authenticate())

        # Case 2: Spoofed IP referer -> must be rejected
        h_spoof = DummyHandler(headers={"Referer": "http://127.0.0.1:8085/api/diagnose"})
        self.assertIsNone(h_spoof._authenticate())

        # Case 3: Legitimate token -> accepted
        h_valid = DummyHandler(headers={"X-API-Token": "dev-token"})
        self.assertEqual(h_valid._authenticate(), "operator")

        # Case 4: Query param token -> accepted
        h_qs = DummyHandler(headers={}, path="/api/diagnose?token=admin-token")
        self.assertEqual(h_qs._authenticate(), "lead_dba")

    def test_simultaneous_diagnostic_sessions(self):
        """Simultaneous diagnostic sessions must remain completely isolated without crosstalk."""
        graph1 = create_ascp_diagnostic_graph()
        graph2 = create_ascp_diagnostic_graph()
        thread1 = "session-concurrent-1"
        thread2 = "session-concurrent-2"

        state1 = graph1.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": ["ORA-00054 on MSC_ST_DEMANDS"]},
            config={"configurable": {"thread_id": thread1}}
        )
        state2 = graph2.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": ["ORA-00054 on MSC_ST_SUPPLIES"]},
            config={"configurable": {"thread_id": thread2}}
        )

        # Both sessions independently encounter Mode 6 lock contention and pause at HITL Gate
        self.assertTrue(state1.get("interrupted"))
        self.assertEqual(state1["interrupt_payload"]["action"], "KILL_SESSION")
        appr1 = state1["interrupt_payload"]["approval_id"]

        self.assertTrue(state2.get("interrupted"))
        self.assertEqual(state2["interrupt_payload"]["action"], "KILL_SESSION")
        appr2 = state2["interrupt_payload"]["approval_id"]

        self.assertNotEqual(appr1, appr2, "Each session must generate a cryptographically unique approval ID!")

        # Resuming Session 1 must succeed and not cross-contaminate Session 2
        resumed1 = graph1.invoke(
            config={"configurable": {"thread_id": thread1}},
            resume_command=Command(resume={"approved": True, "approval_id": appr1, "dba_user": "DBA1"})
        )
        self.assertTrue(resumed1.get("completed"))
        self.assertTrue(resumed1.get("is_remediated"))

        # Session 2 checkpointer still holds its own distinct interrupted state and is NOT remediated
        rec2 = graph2.checkpointer.get_latest(thread2)
        self.assertEqual(rec2.state["interrupt_payload"]["approval_id"], appr2)
        self.assertFalse(rec2.state.get("is_remediated", False))


if __name__ == "__main__":
    unittest.main()
