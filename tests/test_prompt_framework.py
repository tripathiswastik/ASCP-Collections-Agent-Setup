"""Unit tests for the 6-Layer Prompt Stratification & Self-Healing Schema Validation Loop."""

import unittest
from ascp_agent.prompt_framework import StratifiedPromptBuilder, ConfidenceComponents
from ascp_agent.schema_validator import (
    DiagnosticReport,
    validate_schema_node,
    check_validation_routing,
    SchemaValidationError
)

class TestPromptStratificationFramework(unittest.TestCase):
    def test_prompt_assembly_contains_all_six_layers(self):
        payload = '{"LOG": "ORA-00054 on MSC_ST_DEMANDS"}'
        prompt = StratifiedPromptBuilder.assemble_prompt(payload)

        # 1. P_Role
        self.assertIn("SYSTEM PERSONA:", prompt)
        self.assertIn("Lead Oracle ASCP & Enterprise Concurrent Processing Diagnostic Engine", prompt)

        # 2. C_Domain
        self.assertIn("DOMAIN KNOWLEDGE BASE:", prompt)
        self.assertIn("MSC_ST_SYSTEM_ITEMS", prompt)
        self.assertIn("cmclean.sql", prompt)

        # 3. I_Task
        self.assertIn("DIAGNOSTIC TASK INSTRUCTIONS:", prompt)
        self.assertIn("Calculate diagnostic confidence score", prompt)

        # 4. S_Schema
        self.assertIn("REQUIRED JSON SCHEMA:", prompt)
        self.assertIn("diagnostic_summary", prompt)
        self.assertIn("remediation_plan", prompt)

        # 5. K_Constraints
        self.assertIn("OUTPUT CONTRACT & CONSTRAINTS:", prompt)
        self.assertIn("DO NOT wrap the output in markdown code fences", prompt)

        # 6. D_Context
        self.assertIn("INPUT DATA FOR ANALYSIS:", prompt)
        self.assertIn(payload, prompt)

    def test_weighted_confidence_calculation(self):
        # Full match: 0.4*1.0 + 0.4*1.0 + 0.2*1.0 = 1.00
        score = StratifiedPromptBuilder.calculate_confidence(s_error=1.0, s_trace=1.0, s_state=1.0)
        self.assertEqual(score, 1.00)

        # Partial match: 0.4*1.0 + 0.4*0.8 + 0.2*0.5 = 0.4 + 0.32 + 0.10 = 0.82
        score_partial = StratifiedPromptBuilder.calculate_confidence(s_error=1.0, s_trace=0.8, s_state=0.5)
        self.assertEqual(score_partial, 0.82)

    def test_negative_constraints_markdown_fence_cleaning(self):
        dirty_output = """```json
{
  "diagnostic_summary": {
    "failing_stage": "ODS_LOAD",
    "failing_program_short_name": "MSCPDCW",
    "request_id": 890415,
    "primary_error_code": "ORA-00054",
    "confidence_score": 0.96
  },
  "root_cause_analysis": {
    "summary": "Exclusive TM Mode 6 lock",
    "affected_objects": ["MSC_ST_DEMANDS"],
    "is_infrastructure_issue": false,
    "is_data_validation_issue": false
  },
  "remediation_plan": {
    "immediate_action_required": "Terminate SID 412",
    "sql_scripts_to_execute": ["ALTER SYSTEM KILL SESSION '412,28419' IMMEDIATE"],
    "os_commands_to_execute": [],
    "profile_option_adjustments": [],
    "requires_manager_bounce": false
  }
}
```"""
        cleaned = StratifiedPromptBuilder.clean_json_output(dirty_output)
        self.assertFalse(cleaned.startswith("```"))
        self.assertFalse(cleaned.endswith("```"))

        report = DiagnosticReport.model_validate_json(cleaned)
        self.assertEqual(report.diagnostic_summary.primary_error_code, "ORA-00054")
        self.assertEqual(report.diagnostic_summary.confidence_score, 0.96)
        self.assertTrue(report.requires_human_approval)  # Because of KILL SESSION

    def test_self_healing_validation_retry_loop(self):
        # 1. Invalid JSON causes retry increment
        invalid_state = {"raw_llm_output": "Not a JSON document", "retry_count": 0}
        res = validate_schema_node(invalid_state)
        self.assertFalse(res["is_validated"])
        self.assertEqual(res["retry_count"], 1)

        # 2. check_validation_routing routes back to LLM for retries <= 3
        route = check_validation_routing(res)
        self.assertEqual(route, "llm_diagnostic_node")

        # 3. If retry_count > 3, routes to fallback escalation
        exhausted_state = {"is_validated": False, "retry_count": 4}
        route_esc = check_validation_routing(exhausted_state)
        self.assertEqual(route_esc, "fallback_escalation_node")

        # 4. Valid JSON routes to approval or execution
        valid_json = """{
          "diagnostic_summary": {
            "failing_stage": "ODS_LOAD",
            "failing_program_short_name": "MSCPDCW",
            "request_id": 890415,
            "primary_error_code": "ORA-00054",
            "confidence_score": 0.96
          },
          "root_cause_analysis": {
            "summary": "Lock contention",
            "affected_objects": ["MSC_ST_DEMANDS"],
            "is_infrastructure_issue": false,
            "is_data_validation_issue": false
          },
          "remediation_plan": {
            "immediate_action_required": "Kill session",
            "sql_scripts_to_execute": ["ALTER SYSTEM KILL SESSION '412,28419' IMMEDIATE"],
            "os_commands_to_execute": [],
            "profile_option_adjustments": [],
            "requires_manager_bounce": false
          }
        }"""
        valid_state = {"raw_llm_output": valid_json, "retry_count": 1}
        valid_res = validate_schema_node(valid_state)
        self.assertTrue(valid_res["is_validated"])
        self.assertTrue(valid_res["requires_human_approval"])
        route_approved = check_validation_routing(valid_res)
        self.assertEqual(route_approved, "human_approval_node")

if __name__ == "__main__":
    unittest.main()
