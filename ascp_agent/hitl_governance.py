"""Human-in-the-Loop (HITL) Governance Matrix & Approval Engine.
Implements risk tiers (LOW, MEDIUM, HIGH) to safeguard production databases
from unauthorized session termination or destructive DDL/DML.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

@dataclass
class HITLGovernanceRule:
    risk_tier: str  # LOW, MEDIUM, HIGH
    action_type: str
    target_object: str
    requires_mandatory_approval: bool
    requires_dry_run_validation: bool
    description: str

GOVERNANCE_RULES: Dict[str, HITLGovernanceRule] = {
    "INSPECT_LOCKS": HITLGovernanceRule(
        risk_tier="LOW",
        action_type="Read-only Database Introspection",
        target_object="V$SESSION, V$LOCKED_OBJECT",
        requires_mandatory_approval=False,
        requires_dry_run_validation=False,
        description="Zero-risk dynamic performance view querying. Auto-runs without operator approval."
    ),
    "PARSE_LOGS": HITLGovernanceRule(
        risk_tier="LOW",
        action_type="Log & Trace Text Parsing",
        target_object="Concurrent Request Logs",
        requires_mandatory_approval=False,
        requires_dry_run_validation=False,
        description="Read-only text file parsing. Auto-runs without operator approval."
    ),
    "PURGE_STAGING": HITLGovernanceRule(
        risk_tier="MEDIUM",
        action_type="Staging Interface Truncation",
        target_object="MSC_ST_*",
        requires_mandatory_approval=False,
        requires_dry_run_validation=True,
        description="Truncates temporary interface tables. Auto-runs if dry-run validation passes; pauses on schema conflict."
    ),
    "RERUN_SNAPSHOT_FAST": HITLGovernanceRule(
        risk_tier="LOW",
        action_type="Materialized View Fast Refresh",
        target_object="MLOG$_*",
        requires_mandatory_approval=False,
        requires_dry_run_validation=False,
        description="Re-invokes DBMS_SNAPSHOT.REFRESH in fast incremental mode."
    ),
    "REBUILD_ALIGN_INDEXES": HITLGovernanceRule(
        risk_tier="MEDIUM",
        action_type="Partition Index Realignment",
        target_object="MSC_* Partitions",
        requires_mandatory_approval=True,
        requires_dry_run_validation=True,
        description="Realigns index definitions and constraints across staging and ODS structures."
    ),
    "KILL_SESSION": HITLGovernanceRule(
        risk_tier="HIGH",
        action_type="Session Termination",
        target_object="Database Session / Process",
        requires_mandatory_approval=True,
        requires_dry_run_validation=True,
        description="Mandatory HITL Gate. Terminates blocking session via ALTER SYSTEM KILL SESSION. Requires explicit DBA sign-off."
    ),
    "RESET_PIPE": HITLGovernanceRule(
        risk_tier="MEDIUM",
        action_type="DBMS_PIPE Buffer Purge",
        target_object="V$DB_PIPES",
        requires_mandatory_approval=True,
        requires_dry_run_validation=False,
        description="Clears orphan worker pipes and resets buffer allocations."
    ),
    "CMCLEAN_EXEC": HITLGovernanceRule(
        risk_tier="HIGH",
        action_type="Concurrent Manager Cleanup & Process Termination",
        target_object="FND_CONCURRENT_REQUESTS / FND_CONCURRENT_PROCESSES",
        requires_mandatory_approval=True,
        requires_dry_run_validation=True,
        description="Mandatory HITL Gate. Executes cmclean.sql to abort hung concurrent managers. Requires explicit DBA sign-off."
    )
}

class HITLGovernanceEngine:
    """Evaluates requested remediation actions against enterprise governance policies."""

    @staticmethod
    def evaluate_action_risk(action: str) -> HITLGovernanceRule:
        return GOVERNANCE_RULES.get(
            action,
            HITLGovernanceRule("HIGH", action, "UNKNOWN", True, True, "Uncataloged action defaulted to HIGH risk.")
        )

    @staticmethod
    def evaluate_governance_routing(action: str, confidence_score: float) -> str:
        """Determines routing policy:
        - Low-risk read-only diagnostics with confidence >= 85.0% route directly to ServiceNow ticket creation.
        - High-risk or destructive actions (KILL_SESSION, CMCLEAN_EXEC) must invoke interrupt() for DBA sign-off.
        """
        rule = HITLGovernanceEngine.evaluate_action_risk(action)
        if rule.risk_tier == "HIGH" or action in ["KILL_SESSION", "CMCLEAN_EXEC"]:
            return "MANDATORY_HITL_INTERRUPT"
        if rule.risk_tier == "LOW" and confidence_score >= 85.0:
            return "AUTOMATED_SERVICENOW_DISPATCH"
        if rule.risk_tier == "MEDIUM":
            return "CONDITIONAL_INTERRUPT" if confidence_score < 85.0 else "AUTOMATED_EXECUTION"
        return "MANDATORY_HITL_INTERRUPT"

    @staticmethod
    def format_approval_payload(
        action: str,
        target_sid: Optional[int] = None,
        target_serial: Optional[int] = None,
        target_object: Optional[str] = None,
        lock_mode: Optional[str] = None,
        reasoning: Optional[str] = None
    ) -> Dict[str, Any]:
        """Constructs structured approval request payload for HITL gates."""
        rule = HITLGovernanceEngine.evaluate_action_risk(action)
        return {
            "approval_required": rule.requires_mandatory_approval,
            "risk_tier": rule.risk_tier,
            "action": action,
            "action_type": rule.action_type,
            "target_sid": target_sid,
            "target_serial": target_serial,
            "target_object": target_object or rule.target_object,
            "lock_mode": lock_mode,
            "description": rule.description,
            "reasoning": reasoning or f"Agent identified {action} as critical remediation step to unblock ASCP pipeline.",
            "recommended_sql": f"ALTER SYSTEM KILL SESSION '{target_sid},{target_serial}' IMMEDIATE;" if action == "KILL_SESSION" else (
                "START cmclean.sql;" if action == "CMCLEAN_EXEC" else f"EXEC MSC_CL_PULL.PURGE_STAGING_TABLES_SUB();"
            )
        }
