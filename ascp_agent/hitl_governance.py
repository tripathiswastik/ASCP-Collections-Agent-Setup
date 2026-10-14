"""Human-in-the-Loop (HITL) Governance Matrix & Approval Engine.
Implements risk tiers (LOW, MEDIUM, HIGH) to safeguard production databases
from unauthorized session termination or destructive DDL/DML.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class HITLGovernanceRule:
    risk_tier: str  # LOW, MEDIUM, HIGH
    action_type: str
    target_object: str
    requires_mandatory_approval: bool
    requires_dry_run_validation: bool
    description: str

GOVERNANCE_RULES: dict[str, HITLGovernanceRule] = {
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
        risk_tier="HIGH",
        action_type="Staging Interface Truncation",
        target_object="MSC_ST_*",
        requires_mandatory_approval=True,
        requires_dry_run_validation=True,
        description="Mandatory HITL Gate. Truncates temporary interface tables (MSC_ST_*). Potentially destructive; requires explicit DBA sign-off."
    ),
    "PURGE_STAGING_NO_VALIDATION": HITLGovernanceRule(
        risk_tier="HIGH",
        action_type="Staging Interface Truncation (Forced)",
        target_object="MSC_ST_*",
        requires_mandatory_approval=True,
        requires_dry_run_validation=True,
        description="Mandatory HITL Gate. Forces truncation of temporary interface tables without validation. Destructive; requires explicit DBA sign-off."
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
    ),
    "RESET_REGISTRY": HITLGovernanceRule(
        risk_tier="HIGH",
        action_type="Staging Status Registry Reset",
        target_object="MSC_APPS_INSTANCES.ST_STATUS",
        requires_mandatory_approval=True,
        requires_dry_run_validation=True,
        description="Mandatory HITL Gate. Resets ST_STATUS registry flag to 0 (IDLE) following abnormal collection crash. Requires explicit DBA sign-off."
    ),
    "EXTEND_UNDO_RETENTION": HITLGovernanceRule(
        risk_tier="LOW",
        action_type="Dynamic Parameter Adjustment",
        target_object="V$PARAMETER.UNDO_RETENTION",
        requires_mandatory_approval=False,
        requires_dry_run_validation=False,
        description="Non-destructive dynamic parameter increase to eliminate ORA-01555 snapshot too old stalls."
    ),
    "EXTEND_TABLESPACE": HITLGovernanceRule(
        risk_tier="MEDIUM",
        action_type="Storage Quota Allocation",
        target_object="DBA_TABLESPACES",
        requires_mandatory_approval=True,
        requires_dry_run_validation=False,
        description="Adds autoextensible storage to staging tablespaces to prevent ORA-01653 extent exhaustion."
    ),
    "FLUSH_SHARED_POOL": HITLGovernanceRule(
        risk_tier="MEDIUM",
        action_type="SGA Memory Maintenance",
        target_object="V$SGASTAT.SHARED_POOL",
        requires_mandatory_approval=True,
        requires_dry_run_validation=False,
        description="Flushes SGA shared pool heap to remediate ORA-04031 library cache fragmentation."
    ),
    "PURGE_PIPE": HITLGovernanceRule(
        risk_tier="MEDIUM",
        action_type="DBMS_PIPE Buffer Purge",
        target_object="V$DB_PIPES",
        requires_mandatory_approval=True,
        requires_dry_run_validation=False,
        description="Clears orphan worker pipes and resets buffer allocations."
    ),
    "REFRESH_SNAPSHOT": HITLGovernanceRule(
        risk_tier="LOW",
        action_type="Materialized View Fast Refresh",
        target_object="MLOG$_*",
        requires_mandatory_approval=False,
        requires_dry_run_validation=False,
        description="Re-invokes DBMS_SNAPSHOT.REFRESH in fast incremental mode."
    ),
    "ALIGN_INDEXES": HITLGovernanceRule(
        risk_tier="MEDIUM",
        action_type="Partition Index Realignment",
        target_object="MSC_* Partitions",
        requires_mandatory_approval=True,
        requires_dry_run_validation=True,
        description="Realigns index definitions and constraints across staging and ODS structures."
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
        if rule.requires_mandatory_approval or rule.risk_tier == "HIGH":
            return "MANDATORY_HITL_INTERRUPT"
        if rule.risk_tier == "LOW" and confidence_score >= 85.0:
            return "AUTOMATED_SERVICENOW_DISPATCH"
        if rule.risk_tier == "MEDIUM":
            return "CONDITIONAL_INTERRUPT" if confidence_score < 85.0 else "AUTOMATED_EXECUTION"
        return "MANDATORY_HITL_INTERRUPT"

    @staticmethod
    def format_approval_payload(
        action: str,
        target_sid: int | None = None,
        target_serial: int | None = None,
        target_object: str | None = None,
        lock_mode: str | None = None,
        reasoning: str | None = None
    ) -> dict[str, Any]:
        """Constructs structured approval request payload for HITL gates."""
        rule = HITLGovernanceEngine.evaluate_action_risk(action)
        from ascp_agent.remediation import format_kill_session_sql, format_purge_staging_sql
        if action == "KILL_SESSION" and target_sid and target_serial:
            rec_sql = format_kill_session_sql(target_sid, target_serial)
        elif action == "CMCLEAN_EXEC":
            rec_sql = "START cmclean.sql;"
        else:
            rec_sql = format_purge_staging_sql()

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
            "recommended_sql": rec_sql
        }
