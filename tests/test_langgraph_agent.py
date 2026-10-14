"""Unit tests for LangGraph State Machine, Checkpointing, and HITL Gates."""

from __future__ import annotations

import unittest

from ascp_agent.graph import create_ascp_diagnostic_graph
from ascp_agent.state import AIMessage, Command, DiagnosticState, HumanMessage


class TestLangGraphAgent(unittest.TestCase):
    def setUp(self):
        self.graph = create_ascp_diagnostic_graph()

    def test_state_reducers_preserve_history(self):
        state = DiagnosticState()
        state.apply_update({"messages": [HumanMessage("Step 1")]})
        self.assertEqual(len(state["messages"]), 1)
        state.apply_update({"messages": [AIMessage("Step 2")]})
        self.assertEqual(len(state["messages"]), 2)
        state.apply_update({"lock_telemetry": [{"sid": 100}]})
        state.apply_update({"lock_telemetry": [{"sid": 200}]})
        self.assertEqual(len(state["lock_telemetry"]), 2)

    def test_hitl_interrupt_gate_and_resumption(self):
        # Initial run: should traverse agent -> lock_diagnostic -> agent -> interrupt before remediation
        thread_id = "test-thread-hitl-1"
        paused_state = self.graph.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS"},
            config={"configurable": {"thread_id": thread_id}}
        )

        self.assertTrue(paused_state["interrupted"])
        self.assertIsNotNone(paused_state["interrupt_payload"])
        self.assertEqual(paused_state["interrupt_payload"]["action"], "KILL_SESSION")
        self.assertEqual(paused_state["interrupt_payload"]["risk_tier"], "HIGH")

        # Resume run: simulate human operator approving execution
        resume_cmd = Command(resume={"approved": True, "dba_user": "TEST_DBA"})
        resumed_state = self.graph.invoke(
            config={"configurable": {"thread_id": thread_id}},
            resume_command=resume_cmd
        )

        self.assertFalse(resumed_state["interrupted"])
        self.assertTrue(resumed_state["remediation_approved"])
        self.assertTrue(resumed_state["completed"])
        has_term_msg = any("Successfully terminated blocking" in getattr(m, "content", str(m)) for m in resumed_state["messages"])
        self.assertTrue(has_term_msg)

    def test_field_reducers_preserve_buffers_and_traces(self):
        state = DiagnosticState()
        state.apply_update({"log_buffers": ["[WORKER_1] Buffer chunk 1"]})
        state.apply_update({"log_buffers": ["[WORKER_2] Buffer chunk 2"]})
        self.assertEqual(len(state["log_buffers"]), 2)

        state.apply_update({"trace_stacks": [{"worker": 1, "stack": "ORA-00054"}]})
        state.apply_update({"trace_stacks": [{"worker": 2, "stack": "ORA-14098"}]})
        self.assertEqual(len(state["trace_stacks"]), 2)

        state.apply_update({"intermediate_query_results": [{"sid": 101, "table": "MSC_ST_DEMANDS"}]})
        state.apply_update({"intermediate_query_results": [{"sid": 102, "table": "MSC_ST_SUPPLIES"}]})
        self.assertEqual(len(state["intermediate_query_results"]), 2)

    def test_send_parallel_fan_out_execution(self):
        worker_logs = [
            {
                "worker_id": "PULL_WORKER_1",
                "table": "MSC_ST_DEMANDS",
                "log_content": "[12-OCT-2025 04:12:05]: Cause: ORA-00054: resource busy on MSC_ST_DEMANDS."
            },
            {
                "worker_id": "PULL_WORKER_2",
                "table": "MSC_ST_SUPPLIES",
                "log_content": "[12-OCT-2025 04:12:06]: Cause: ORA-14098: index mismatch on MSC_ST_SUPPLIES."
            }
        ]

        # Invoke graph with multiple worker logs triggering Send parallel fan-out
        thread_id = "test-thread-send-fanout"
        state = self.graph.invoke(
            initial_state={"worker_logs": worker_logs},
            config={"configurable": {"thread_id": thread_id}}
        )

        self.assertGreaterEqual(len(state["log_buffers"]), 2)
        self.assertGreaterEqual(len(state["intermediate_query_results"]), 2)
        tables = [r["table"] for r in state["intermediate_query_results"]]
        self.assertIn("MSC_ST_DEMANDS", tables)
        self.assertIn("MSC_ST_SUPPLIES", tables)

    def test_postgres_saver_durable_checkpointing(self):
        from ascp_agent.graph import PostgresSaver
        saver = PostgresSaver(dsn=None)  # Standalone fallback mode
        thread_id = "test-thread-postgres-1"
        test_state = DiagnosticState({"failure_domain": "DATABASE_LOCK", "confidence_score": 95.0})
        
        step = saver.save(thread_id, test_state, "next_node_step")
        self.assertEqual(step, 1)

        latest = saver.get_latest(thread_id)
        self.assertIsNotNone(latest)
        self.assertEqual(latest.state["confidence_score"], 95.0)
        self.assertEqual(latest.next_node, "next_node_step")

    def test_idempotent_hitl_re_execution(self):
        from ascp_agent.graph import hitl_gate_node
        # When node is executed on an already remediated state, it should be strictly idempotent
        state = DiagnosticState({
            "is_remediated": True,
            "remediation_approved": True,
            "remediation_action": "KILL_SESSION"
        })
        res = hitl_gate_node(state)
        self.assertTrue(res["is_remediated"])
        self.assertIn("already executed previously", res["messages"][0].content)

    def test_overwrite_wrapper_clears_prior_reducers(self):
        from ascp_agent.state import Overwrite
        state = DiagnosticState()
        # Normal updates accumulate
        state.apply_update({"log_templates": ["Template 1", "Template 2"]})
        self.assertEqual(len(state["log_templates"]), 2)
        state.apply_update({"log_templates": ["Template 3"]})
        self.assertEqual(len(state["log_templates"]), 3)
        # Using Overwrite wrapper resets the array during self-healing loops
        state.apply_update({"log_templates": Overwrite(["Cleaned Template"])})
        self.assertEqual(state["log_templates"], ["Cleaned Template"])

    def test_interrupt_signal_inherits_base_exception(self):
        from ascp_agent.state import InterruptSignal
        # Verify InterruptSignal is a BaseException, not swallowed by generic `except Exception:`
        self.assertTrue(issubclass(InterruptSignal, BaseException))
        swallowed = False
        try:
            try:
                raise InterruptSignal({"action": "KILL_SESSION"})
            except Exception:  # noqa: BLE001 -- test intentionally verifies InterruptSignal bypasses broad Exception
                swallowed = True
        except InterruptSignal:
            swallowed = False
        self.assertFalse(swallowed)

    def test_recursion_limit_and_remaining_steps(self):
        thread_id = "test-thread-recursion-limit"
        state = self.graph.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS"},
            config={"configurable": {"thread_id": thread_id}, "recursion_limit": 50}
        )
        self.assertIn("remaining_steps", state)
        self.assertLess(state["remaining_steps"], 50)

    def test_parse_worker_log_node_preserves_unicode_metadata_for_empty_log(self):
        """Boundary coverage: An empty worker log artifact must not discard identifying Unicode metadata."""
        from ascp_agent.graph import parse_worker_log_node

        result = parse_worker_log_node(
            {
                "worker_id": "作業者-Δ",
                "table": "需要_表",
                "log_content": "",
            }
        )

        self.assertEqual(result["log_templates"], [])
        self.assertEqual(
            result["intermediate_query_results"],
            [{"worker_id": "作業者-Δ", "table": "需要_表", "errors": []}]
        )
        self.assertEqual(
            result["audit_trail"],
            [{"event": "PARALLEL_WORKER_PARSED", "worker_id": "作業者-Δ", "table": "需要_表"}]
        )

if __name__ == "__main__":
    unittest.main()
