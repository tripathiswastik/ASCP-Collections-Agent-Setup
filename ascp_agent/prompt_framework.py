"""6-Layer Structural Stratification Framework for ASCP Diagnostic Prompts.
Implements the mathematical formulation:
Prompt = P_Role + C_Domain + I_Task + D_Context + S_Schema + K_Constraints
and the weighted confidence calculation:
C_diag = 0.4 * S_error_code + 0.4 * S_trace_match + 0.2 * S_state_consistency
"""

import json
import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

@dataclass
class ConfidenceComponents:
    s_error_code: float = 1.0       # 0.0 to 1.0
    s_trace_match: float = 1.0      # 0.0 to 1.0
    s_state_consistency: float = 1.0 # 0.0 to 1.0

    @property
    def c_diag(self) -> float:
        """Weighted evaluation model: C_diag = 0.4*S_err + 0.4*S_trace + 0.2*S_state"""
        score = (0.4 * self.s_error_code) + (0.4 * self.s_trace_match) + (0.2 * self.s_state_consistency)
        return round(min(max(score, 0.0), 1.0), 4)

class StratifiedPromptBuilder:
    """Mathematical 6-Layer Stratification Prompt Engine."""

    P_ROLE = """SYSTEM PERSONA:
You are the Lead Oracle ASCP & Enterprise Concurrent Processing Diagnostic Engine. Your operational function is to ingest unparsed log streams, SQL trace outputs, and concurrent manager queue statuses, diagnose the root cause of collections failures, and output machine-actionable remediation instructions. You must maintain strict operational boundaries: provide deterministic, evidence-based root-cause analysis without speculative assumptions."""

    C_DOMAIN = """DOMAIN KNOWLEDGE BASE:
- ASCP Data Collection Stages: Refresh Snapshots -> Planning Data Pull (PDP) -> Planning ODS Load (PODSL) -> Purge Staging Tables.
- Core Staging Tables: MSC_ST_SYSTEM_ITEMS, MSC_ST_SUPPLIES, MSC_ST_DEMANDS, MSC_ST_TRADING_PARTNERS.
- Core Destination Tables: MSC_SYSTEM_ITEMS, MSC_SUPPLIES, MSC_DEMANDS (Collected data must have PLAN_ID = -1).
- Error Log Tables: MSC_ERRORS (Mapped via TRANSACTION_ID to ST_TRANSACTION_ID of staging tables).
- Concurrent Processing Programs: MSCPDP (Data Pull), MSCODS (ODS Load), MSRCS (Refresh Snapshots), MSCPDCP (Purge Staging).
- Key Executables & Managers: FNDLIBR, INVLIBR, FNDCRM (Conflict Resolution Manager), FNDSM (Service Manager).
- Diagnostic & Recovery Scripts: cmclean.sql (MOS Note 134007.1), FNDCPBWV (Rebuild Views), mscddiag.sql."""

    I_TASK = """DIAGNOSTIC TASK INSTRUCTIONS:
1. Analyze the provided INPUT_LOGS and DATABASE_STATES within the INPUT DATA FOR ANALYSIS payload.
2. Identify the failing pipeline stage (SNAPSHOT_REFRESH, DATA_PULL, ODS_LOAD, CONCURRENT_MANAGER_QUEUE).
3. Extract explicit error codes (e.g., ORA-00054, ORA-00001, ORA-14098, APP-1167, Timeout, Preprocessing Failure).
4. Determine primary root cause and secondary contributing factors.
5. Formulate step-by-step SQL and OS-level remediation commands.
6. Calculate diagnostic confidence score (0.00 to 1.00) using the weighted model:
   C_diag = 0.4 * S_error_code + 0.4 * S_trace_match + 0.2 * S_state_consistency."""

    S_SCHEMA = """REQUIRED JSON SCHEMA:
{
  "diagnostic_summary": {
    "failing_stage": "one of: SNAPSHOT_REFRESH | DATA_PULL | ODS_LOAD | CONCURRENT_QUEUE | DATABASE_LINK | UNKNOWN",
    "failing_program_short_name": "string",
    "request_id": "integer_or_null",
    "primary_error_code": "string",
    "confidence_score": "float_between_0_and_1"
  },
  "root_cause_analysis": {
    "summary": "string",
    "affected_objects": ["array_of_strings"],
    "is_infrastructure_issue": "boolean",
    "is_data_validation_issue": "boolean"
  },
  "remediation_plan": {
    "immediate_action_required": "string",
    "sql_scripts_to_execute": ["array_of_sql_command_strings"],
    "os_commands_to_execute": ["array_of_os_command_strings"],
    "profile_option_adjustments": [
      {
        "profile_option_name": "string",
        "recommended_value": "string"
      }
    ],
    "requires_manager_bounce": "boolean"
  }
}"""

    K_CONSTRAINTS = """OUTPUT CONTRACT & CONSTRAINTS:
You must return ONLY a single, strictly formatted JSON object matching the schema above.
DO NOT wrap the output in markdown code fences (e.g., DO NOT use ```json ... ```).
DO NOT include any prose preambles, introductory text, or concluding remarks."""

    @classmethod
    def assemble_prompt(cls, runtime_payload: str) -> str:
        """Assembles 6-layer stratified prompt: P_Role + C_Domain + I_Task + S_Schema + K_Constraints + D_Context"""
        return f"""{cls.P_ROLE}

{cls.C_DOMAIN}

{cls.I_TASK}

{cls.S_SCHEMA}

{cls.K_CONSTRAINTS}

INPUT DATA FOR ANALYSIS:
{runtime_payload}"""

    @classmethod
    def calculate_confidence(cls, s_error: float, s_trace: float, s_state: float) -> float:
        """Computes weighted diagnostic confidence score."""
        comp = ConfidenceComponents(s_error_code=s_error, s_trace_match=s_trace, s_state_consistency=s_state)
        return comp.c_diag

    @staticmethod
    def clean_json_output(raw_output: str) -> str:
        """Enforces negative constraints compliance by stripping markdown fences if present."""
        clean = raw_output.strip()
        # Remove ```json or ``` if model leaked markdown fences
        clean = re.sub(r"^```(?:json)?\s*", "", clean, flags=re.MULTILINE)
        clean = re.sub(r"\s*```$", "", clean, flags=re.MULTILINE)
        return clean.strip()
