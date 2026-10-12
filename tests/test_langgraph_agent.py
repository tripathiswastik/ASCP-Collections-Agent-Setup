"""Unit tests for LangGraph State Machine, Checkpointing, and HITL Gates."""

import unittest
from ascp_agent.graph import create_ascp_diagnostic_graph
from ascp_agent.state import DiagnosticState, AIMessage, HumanMessage, Command

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

    def test_time_travel_state_history(self):
        thread_id = "test-thread-history"
        self.graph.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS"},
            config={"configurable": {"thread_id": thread_id}}
        )
        history = self.graph.get_state_history({"configurable": {"thread_id": thread_id}})
        self.assertGreater(len(history), 1)

if __name__ == "__main__":
    unittest.main()
