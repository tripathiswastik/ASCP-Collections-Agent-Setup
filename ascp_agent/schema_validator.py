"""Self-Healing Schema Validation Engine and Models for ASCP Diagnostic Agent.
Implements DiagnosticReport validation, schema constraint checking,
retry counting (max 3 retries), and self-healing error feedback.
"""

import json
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from ascp_agent.prompt_framework import StratifiedPromptBuilder

class SchemaValidationError(Exception):
    """Raised when output fails required schema contract."""
    pass

@dataclass
class DiagnosticSummary:
    failing_stage: str
    failing_program_short_name: str
    request_id: Optional[int]
    primary_error_code: str
    confidence_score: float

@dataclass
class RootCauseAnalysis:
    summary: str
    affected_objects: List[str]
    is_infrastructure_issue: bool
    is_data_validation_issue: bool

@dataclass
class ProfileOptionAdjustment:
    profile_option_name: str
    recommended_value: str

@dataclass
class RemediationPlan:
    immediate_action_required: str
    sql_scripts_to_execute: List[str]
    os_commands_to_execute: List[str]
    profile_option_adjustments: List[ProfileOptionAdjustment]
    requires_manager_bounce: bool

@dataclass
class DiagnosticReport:
    diagnostic_summary: DiagnosticSummary
    root_cause_analysis: RootCauseAnalysis
    remediation_plan: RemediationPlan

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DiagnosticReport':
        """Validates and instantiates DiagnosticReport from dictionary."""
        # 1. Validate diagnostic_summary
        summary_raw = data.get("diagnostic_summary")
        if not isinstance(summary_raw, dict):
            raise SchemaValidationError("Missing or invalid 'diagnostic_summary' object.")
        
        valid_stages = {"SNAPSHOT_REFRESH", "DATA_PULL", "ODS_LOAD", "CONCURRENT_QUEUE", "DATABASE_LINK", "UNKNOWN"}
        stage = summary_raw.get("failing_stage", "UNKNOWN")
        if stage not in valid_stages:
            stage = "UNKNOWN"

        conf = float(summary_raw.get("confidence_score", 0.0))
        if conf < 0.0 or conf > 1.0:
            conf = min(max(conf, 0.0), 1.0)

        summary = DiagnosticSummary(
            failing_stage=stage,
            failing_program_short_name=str(summary_raw.get("failing_program_short_name", "")),
            request_id=summary_raw.get("request_id"),
            primary_error_code=str(summary_raw.get("primary_error_code", "")),
            confidence_score=conf
        )

        # 2. Validate root_cause_analysis
        rca_raw = data.get("root_cause_analysis")
        if not isinstance(rca_raw, dict):
            raise SchemaValidationError("Missing or invalid 'root_cause_analysis' object.")

        rca = RootCauseAnalysis(
            summary=str(rca_raw.get("summary", "")),
            affected_objects=list(rca_raw.get("affected_objects", [])),
            is_infrastructure_issue=bool(rca_raw.get("is_infrastructure_issue", False)),
            is_data_validation_issue=bool(rca_raw.get("is_data_validation_issue", False))
        )

        # 3. Validate remediation_plan
        rem_raw = data.get("remediation_plan")
        if not isinstance(rem_raw, dict):
            raise SchemaValidationError("Missing or invalid 'remediation_plan' object.")

        profile_adjustments = []
        for adj in rem_raw.get("profile_option_adjustments", []):
            if isinstance(adj, dict):
                profile_adjustments.append(ProfileOptionAdjustment(
                    profile_option_name=str(adj.get("profile_option_name", "")),
                    recommended_value=str(adj.get("recommended_value", ""))
                ))

        rem = RemediationPlan(
            immediate_action_required=str(rem_raw.get("immediate_action_required", "")),
            sql_scripts_to_execute=list(rem_raw.get("sql_scripts_to_execute", [])),
            os_commands_to_execute=list(rem_raw.get("os_commands_to_execute", [])),
            profile_option_adjustments=profile_adjustments,
            requires_manager_bounce=bool(rem_raw.get("requires_manager_bounce", False))
        )

        return cls(
            diagnostic_summary=summary,
            root_cause_analysis=rca,
            remediation_plan=rem
        )

    @classmethod
    def model_validate_json(cls, json_str: str) -> 'DiagnosticReport':
        """Parses and validates JSON string into DiagnosticReport."""
        clean_str = StratifiedPromptBuilder.clean_json_output(json_str)
        data = json.loads(clean_str)
        return cls.from_dict(data)

    def model_dump(self) -> Dict[str, Any]:
        """Serializes report into dictionary."""
        return asdict(self)

    @property
    def requires_human_approval(self) -> bool:
        """Determines if remediation requires mandatory operator approval."""
        return (
            self.remediation_plan.requires_manager_bounce or
            len(self.remediation_plan.os_commands_to_execute) > 0 or
            any("KILL SESSION" in sql.upper() or "TRUNCATE" in sql.upper() for sql in self.remediation_plan.sql_scripts_to_execute) or
            self.diagnostic_summary.confidence_score < 0.85
        )

# -------------------------------------------------------------
# LangGraph Self-Healing Validation Node & Router
# -------------------------------------------------------------

def validate_schema_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Validates raw LLM output against the required machine-parseable JSON schema."""
    raw_output = state.get("raw_llm_output", "")
    retry_count = state.get("retry_count", 0)

    try:
        validated = DiagnosticReport.model_validate_json(raw_output)
        return {
            "parsed_diagnosis": validated.model_dump(),
            "is_validated": True,
            "confidence_score": validated.diagnostic_summary.confidence_score * 100.0,
            "requires_human_approval": validated.requires_human_approval
        }
    except Exception as err:
        return {
            "is_validated": False,
            "retry_count": retry_count + 1,
            "validation_error": str(err)
        }

def check_validation_routing(state: Dict[str, Any]) -> str:
    """Evaluates validation outcome and routes to remediation, HITL, or self-correction."""
    if state.get("is_validated"):
        if state.get("requires_human_approval"):
            return "human_approval_node"
        return "execute_remediation_node"

    if state.get("retry_count", 0) > 3:
        return "fallback_escalation_node"

    return "llm_diagnostic_node"
