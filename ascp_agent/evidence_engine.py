"""Evidence-Based Root Cause Analysis (RCA) Engine for Oracle ASCP.
Evaluates observed evidence across planning logs, concurrent requests, SQL observations,
and database wait telemetry against structured ASCP diagnostic rules.

Key Capabilities:
- Assembles precise supporting log lines and SQL observations.
- Calculates deterministic confidence from evidence coverage:
    Coverage Score = (Sum of weights of observed evidence / Total rule weights) * 100
- Distinguishes CONFIRMED causes from competing HYPOTHESES.
- Identifies missing evidence before recommending guarded remediation.
- Disambiguates identical top-level symptoms (e.g. Stage 2 ODS crash) into distinct root causes
  (ORA-00054 lock vs ORA-00001 surrogate key collision vs ORA-14098 index mismatch).
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from ascp_agent.knowledge_base import ASCP_KNOWLEDGE_RULES, DiagnosticRule

logger = logging.getLogger(__name__)


@dataclass
class ObservedEvidence:
    """Individual evidence artifact verified by the agent."""
    code: str
    evidence_type: str  # LOG_LINE, SQL_OBSERVATION, METRIC_CHECK
    raw_content: str  # Exact log line or serialized SQL row observation
    matched_pattern: str
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisEvaluation:
    """Evaluated diagnosis candidate ranked by evidence coverage."""
    rule_id: str
    title: str
    subsystem: str
    domain: str
    status: str  # CONFIRMED or HYPOTHESIS or REFUTED
    confidence_score: float  # 0.0 - 100.0%
    observed_signatures: list[str] = field(default_factory=list)
    supporting_evidence: list[ObservedEvidence] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    competing_hypotheses: list[str] = field(default_factory=list)
    safe_next_checks: list[str] = field(default_factory=list)
    remediation_action: str | None = None
    remediation_spec: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "subsystem": self.subsystem,
            "domain": self.domain,
            "status": self.status,
            "confidence_score": round(self.confidence_score, 1),
            "observed_signatures": self.observed_signatures,
            "supporting_evidence": [e.to_dict() for e in self.supporting_evidence],
            "missing_evidence": self.missing_evidence,
            "competing_hypotheses": self.competing_hypotheses,
            "safe_next_checks": self.safe_next_checks,
            "remediation_action": self.remediation_action,
            "remediation_spec": self.remediation_spec,
        }


@dataclass
class DiagnosticFinding:
    """Complete evidence-backed RCA finding ready for display and governance."""
    primary_diagnosis: HypothesisEvaluation
    ranked_hypotheses: list[HypothesisEvaluation]
    supporting_log_lines: list[str]
    supporting_sql_observations: list[dict[str, Any]]
    unresolved_uncertainties: list[str]
    overall_confidence: float
    can_proceed_to_remediation: bool
    remediation_blockers: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary_diagnosis": self.primary_diagnosis.to_dict(),
            "ranked_hypotheses": [h.to_dict() for h in self.ranked_hypotheses],
            "supporting_log_lines": self.supporting_log_lines,
            "supporting_sql_observations": self.supporting_sql_observations,
            "unresolved_uncertainties": self.unresolved_uncertainties,
            "overall_confidence": round(self.overall_confidence, 1),
            "can_proceed_to_remediation": self.can_proceed_to_remediation,
            "remediation_blockers": self.remediation_blockers,
        }


class EvidenceAnalysisEngine:
    """Assembles evidence across sources and evaluates diagnostic rules."""

    def __init__(self, rules: dict[str, DiagnosticRule] | None = None):
        self.rules = rules or ASCP_KNOWLEDGE_RULES

    def assemble_evidence(
        self,
        logs: list[str],
        lock_telemetry: list[dict[str, Any]] | None = None,
        db_metrics: dict[str, Any] | None = None,
        concurrent_requests: list[dict[str, Any]] | None = None,
    ) -> list[ObservedEvidence]:
        """Scans logs, lock telemetry, and metrics to extract concrete evidence items."""
        evidence: list[ObservedEvidence] = []
        lock_telemetry = lock_telemetry or []
        db_metrics = db_metrics or {}
        concurrent_requests = concurrent_requests or []

        # 1. Extract log line evidence
        for line in logs:
            line_str = line.strip()
            if not line_str:
                continue

            # Check for ORA-00054 / Mode 6
            if "ORA-00054" in line_str or "resource busy and acquire with NOWAIT" in line_str:
                evidence.append(
                    ObservedEvidence(
                        code="LOG_ORA_00054",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="ORA-00054",
                        weight=1.5,
                    )
                )

            # Check for ORA-00001
            if "ORA-00001" in line_str or "unique constraint" in line_str:
                evidence.append(
                    ObservedEvidence(
                        code="LOG_ORA_00001",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="ORA-00001",
                        weight=1.5,
                    )
                )

            # Check for ORA-14098
            if "ORA-14098" in line_str or "index mismatch" in line_str:
                evidence.append(
                    ObservedEvidence(
                        code="LOG_ORA_14098",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="ORA-14098",
                        weight=1.5,
                    )
                )

            # Check for ORA-12571
            if "ORA-12571" in line_str or "packet writer failure" in line_str:
                evidence.append(
                    ObservedEvidence(
                        code="LOG_ORA_12571",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="ORA-12571",
                        weight=1.5,
                    )
                )

            # Check for ORA-02478
            if "ORA-02478" in line_str or "maxextents reached" in line_str or "DBMS_PIPE" in line_str:
                evidence.append(
                    ObservedEvidence(
                        code="LOG_ORA_02478",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="ORA-02478",
                        weight=1.5,
                    )
                )

            # Check for ORA-00060
            if "ORA-00060" in line_str or "deadlock detected" in line_str:
                evidence.append(
                    ObservedEvidence(
                        code="LOG_ORA_00060",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="ORA-00060",
                        weight=1.5,
                    )
                )

            # Check for ORA-01555
            if "ORA-01555" in line_str or "snapshot too old" in line_str:
                evidence.append(
                    ObservedEvidence(
                        code="LOG_ORA_01555",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="ORA-01555",
                        weight=1.5,
                    )
                )

            # Check for ORA-01653
            if "ORA-01653" in line_str or "unable to extend table" in line_str:
                evidence.append(
                    ObservedEvidence(
                        code="LOG_ORA_01653",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="ORA-01653",
                        weight=1.5,
                    )
                )

            # Check for ORA-04031
            if "ORA-04031" in line_str or "unable to allocate" in line_str or "shared memory" in line_str:
                evidence.append(
                    ObservedEvidence(
                        code="LOG_ORA_04031",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="ORA-04031",
                        weight=1.5,
                    )
                )

            # Check for ST_STATUS stuck in active state
            if "ST_STATUS is not zero" in line_str or "ST_STATUS = 2" in line_str or "ST_STATUS = 1" in line_str:
                evidence.append(
                    ObservedEvidence(
                        code="LOG_STUCK_ST_STATUS",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="ST_STATUS",
                        weight=1.5,
                    )
                )

            # Check for Resource bottleneck / Capacity overload
            if "Resource overload" in line_str or "capacity exceeded" in line_str or "overload hours" in line_str.lower():
                evidence.append(
                    ObservedEvidence(
                        code="LOG_RESOURCE_OVERLOAD",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="RESOURCE_OVERLOAD",
                        weight=1.2,
                    )
                )

            # Check for Sourcing Rule loop or missing calendar
            if "sourcing loop" in line_str.lower() or "circular sourcing" in line_str.lower() or "missing workday calendar" in line_str.lower():
                evidence.append(
                    ObservedEvidence(
                        code="LOG_SOURCING_ERROR",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="SOURCING_RULE",
                        weight=1.2,
                    )
                )

            # Check for Worker termination
            if "Worker process" in line_str and ("terminated" in line_str or "aborted" in line_str):
                evidence.append(
                    ObservedEvidence(
                        code="LOG_WORKER_ABORT",
                        evidence_type="LOG_LINE",
                        raw_content=line_str,
                        matched_pattern="Worker terminated",
                        weight=1.0,
                    )
                )

        # 2. Extract database lock observation evidence
        for lk in lock_telemetry:
            sid = lk.get("sid")
            mode = lk.get("locked_mode_text", "")
            depth = lk.get("lock_depth", 0)
            obj = lk.get("object_name", "")

            if depth == 1 or lk.get("blocking_session") is None:
                # Root blocker
                if "Mode 6" in mode or "Exclusive" in mode or lk.get("locked_mode") == 6:
                    evidence.append(
                        ObservedEvidence(
                            code="SQL_ROOT_BLOCKER_MODE6",
                            evidence_type="SQL_OBSERVATION",
                            raw_content=f"Root blocker SID {sid} holding Mode 6 Exclusive lock on {obj}",
                            matched_pattern="LOCKED_MODE=6",
                            weight=2.0,
                        )
                    )
                elif "deadlock" in mode.lower() or "deadlock" in str(lk.get("event", "")).lower():
                    evidence.append(
                        ObservedEvidence(
                            code="SQL_DEADLOCK_CYCLE",
                            evidence_type="SQL_OBSERVATION",
                            raw_content=f"Mutual lock wait cycle isolated on {obj} involving SID {sid}",
                            matched_pattern="DEADLOCK_CYCLE",
                            weight=2.0,
                        )
                    )
                else:
                    evidence.append(
                        ObservedEvidence(
                            code="SQL_LOCK_OBSERVED",
                            evidence_type="SQL_OBSERVATION",
                            raw_content=f"Lock held by SID {sid} on {obj} (mode: {mode})",
                            matched_pattern="LOCK_HELD",
                            weight=1.0,
                        )
                    )

        # 3. Extract DB metrics & Collection registry status
        if db_metrics.get("st_status") is not None:
            st_val = db_metrics.get("st_status")
            if st_val in (1, 2, -1):
                active_workers = db_metrics.get("active_workers", 0)
                if active_workers == 0:
                    evidence.append(
                        ObservedEvidence(
                            code="SQL_ST_STATUS_NONZERO_NO_WORKERS",
                            evidence_type="SQL_OBSERVATION",
                            raw_content=f"MSC_APPS_INSTANCES.ST_STATUS is {st_val} with 0 active workers (stalled lock)",
                            matched_pattern=f"ST_STATUS={st_val}",
                            weight=1.8,
                        )
                    )

        # 4. Check for baseline healthy evidence
        if not evidence and logs:
            has_completed = any("completed successfully" in line.lower() or "records loaded" in line.lower() for line in logs)
            if has_completed:
                evidence.append(
                    ObservedEvidence(
                        code="LOG_HEALTHY_ETL_COMPLETED",
                        evidence_type="LOG_LINE",
                        raw_content="All ETL stages completed successfully with zero fatal errors.",
                        matched_pattern="COMPLETED_SUCCESSFULLY",
                        weight=2.0,
                    )
                )

        return evidence

    def evaluate(
        self,
        logs: list[str],
        lock_telemetry: list[dict[str, Any]] | None = None,
        db_metrics: dict[str, Any] | None = None,
        concurrent_requests: list[dict[str, Any]] | None = None,
    ) -> DiagnosticFinding:
        """Evaluates observed evidence against all structured diagnostic rules using
        explicit signature pattern matching across logs, lock telemetry, and metrics.
        """
        lock_telemetry = lock_telemetry or []
        db_metrics = db_metrics or {}
        concurrent_requests = concurrent_requests or []
        all_logs_text = " ".join(logs).lower()

        hypotheses: list[HypothesisEvaluation] = []

        for rule in self.rules.values():
            matched_evidence: list[ObservedEvidence] = []
            matched_weights = 0.0
            total_possible_weights = sum(sig.weight for sig in rule.evidence_signatures) or 1.0
            missing_signatures: list[str] = []
            has_all_mandatory = True

            for sig in rule.evidence_signatures:
                sig_matched = False
                matched_detail = ""

                # 1. Log Pattern Signatures
                if sig.evidence_type == "LOG_PATTERN":
                    req_match = (sig.required_match or "").lower()
                    for line in logs:
                        if req_match and req_match in line.lower():
                            sig_matched = True
                            matched_detail = line.strip()
                            break
                    if not sig_matched and sig.code.lower() in all_logs_text:
                        sig_matched = True
                        matched_detail = f"Pattern {sig.code} matched in execution logs."

                # 2. Database Lock / SQL Query Signatures
                elif sig.evidence_type in ("SQL_QUERY", "SQL_OBSERVATION"):
                    req_match = (sig.required_match or "").upper()
                    if req_match == "MODE_6_EXCLUSIVE" or "MODE6" in sig.code or "LOCK-ROOT" in sig.code:
                        for lk in lock_telemetry:
                            mode = str(lk.get("locked_mode_text", "")).upper()
                            val = lk.get("locked_mode")
                            if val == 6 or "EXCLUSIVE" in mode or "MODE 6" in mode:
                                sig_matched = True
                                sid = lk.get("sid", 0)
                                obj = lk.get("object_name", "MSC table")
                                matched_detail = f"Root blocker SID {sid} holding Mode 6 Exclusive lock on {obj}"
                                break
                    elif "DEADLOCK" in req_match or "DEADLOCK" in sig.code:
                        for lk in lock_telemetry:
                            if "deadlock" in str(lk.get("event", "")).lower() or "deadlock" in str(lk.get("locked_mode_text", "")).lower():
                                sig_matched = True
                                matched_detail = "Mutual circular lock wait isolated in V$LOCKED_OBJECT."
                                break
                        if not sig_matched and ("ora-00060" in all_logs_text or "deadlock" in all_logs_text):
                            sig_matched = True
                            matched_detail = "Deadlock cycle reported in alert log trace."

                # 3. Registry State Signatures
                elif sig.evidence_type in ("REGISTRY_STATE", "METRIC_CHECK"):
                    req_match = sig.required_match or ""
                    st_val = db_metrics.get("st_status")
                    if "ST_STATUS = -1" in req_match and st_val == -1:
                        sig_matched = True
                        matched_detail = "MSC_APPS_INSTANCES.ST_STATUS is -1 (crashed/incomplete)."
                    elif "ST_STATUS = 2" in req_match and st_val == 2:
                        sig_matched = True
                        matched_detail = "MSC_APPS_INSTANCES.ST_STATUS is 2 (LOAD_PROCESSING)."
                    elif "ST_STATUS = 0" in req_match and st_val == 0:
                        sig_matched = True
                        matched_detail = "MSC_APPS_INSTANCES.ST_STATUS is 0 (clean idle baseline)."

                if sig_matched:
                    obs_item = ObservedEvidence(
                        code=sig.code,
                        evidence_type=sig.evidence_type,
                        raw_content=matched_detail,
                        matched_pattern=sig.required_match or sig.code,
                        weight=sig.weight,
                    )
                    matched_evidence.append(obs_item)
                    matched_weights += sig.weight
                else:
                    if sig.is_mandatory:
                        has_all_mandatory = False
                        missing_signatures.append(f"{sig.code}: {sig.description}")

            if not matched_evidence:
                continue

            # Calculate evidence coverage score
            coverage_pct = round(min(100.0, (matched_weights / total_possible_weights) * 100.0), 1)

            # Determine whether this is CONFIRMED or a HYPOTHESIS
            status = "CONFIRMED" if (has_all_mandatory and coverage_pct >= 65.0) else "HYPOTHESIS"

            rem_spec_dict = None
            if rule.remediation_spec:
                rem_spec_dict = {
                    "action_name": rule.remediation_spec.action_name,
                    "risk_tier": rule.remediation_spec.risk_tier.value,
                    "requires_approval": rule.remediation_spec.requires_approval,
                    "requires_dry_run": rule.remediation_spec.requires_dry_run,
                    "description": rule.remediation_spec.description,
                    "recommended_sql": rule.remediation_spec.recommended_sql,
                    "preconditions": rule.remediation_spec.preconditions,
                    "rollback_plan": rule.remediation_spec.rollback_plan,
                    "verification_check": rule.remediation_spec.verification_check,
                }

            hypotheses.append(
                HypothesisEvaluation(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    subsystem=rule.subsystem,
                    domain=rule.domain.value,
                    status=status,
                    confidence_score=coverage_pct,
                    observed_signatures=[e.code for e in matched_evidence],
                    supporting_evidence=matched_evidence,
                    missing_evidence=missing_signatures,
                    competing_hypotheses=rule.competing_hypotheses,
                    safe_next_checks=rule.safe_next_checks,
                    remediation_action=rule.remediation_spec.action_name if rule.remediation_spec else None,
                    remediation_spec=rem_spec_dict,
                )
            )

        # Sort hypotheses by confidence score descending
        hypotheses.sort(key=lambda h: (h.status == "CONFIRMED", h.confidence_score), reverse=True)

        if hypotheses:
            primary = hypotheses[0]
            ranked = hypotheses[1:]
        else:
            # Fallback when no specific failure signature triggered
            primary = HypothesisEvaluation(
                rule_id="RULE_UNKNOWN_SYMPTOM",
                title="Unclassified ASCP Telemetry / Healthy Run",
                subsystem="General Diagnostic Monitor",
                domain="HEALTHY_BASELINE",
                status="HYPOTHESIS",
                confidence_score=50.0,
                observed_signatures=[],
                supporting_evidence=[],
                missing_evidence=["Need live concurrent manager log and V$SESSION wait details."],
                competing_hypotheses=[],
                safe_next_checks=["Check concurrent manager request log", "Inspect active V$SESSION"],
                remediation_action="INSPECT_LOCKS",
            )
            ranked = []

        # Collect supporting lines and SQL
        log_lines = [e.raw_content for e in primary.supporting_evidence if e.evidence_type == "LOG_LINE"]
        sql_obs = [{"description": e.raw_content, "code": e.code} for e in primary.supporting_evidence if e.evidence_type == "SQL_OBSERVATION"]

        # Blocker check: Destructive action cannot proceed if missing mandatory evidence
        can_proceed = True
        blockers: list[str] = []

        if primary.status != "CONFIRMED":
            can_proceed = False
            blockers.append(f"Diagnosis is only a HYPOTHESIS ({primary.confidence_score:.1f}% confidence); missing mandatory evidence.")

        if primary.missing_evidence:
            can_proceed = False
            for m in primary.missing_evidence:
                blockers.append(f"Missing required telemetry: {m}")

        # If action is KILL_SESSION, ensure SQL blocker was explicitly observed
        if primary.remediation_action == "KILL_SESSION":
            has_blocker_obs = any(e.code in ("SQL_ROOT_BLOCKER_MODE6", "EV-LOCK-ROOT-BLOCKER") for e in primary.supporting_evidence)
            if not has_blocker_obs and not lock_telemetry:
                can_proceed = False
                blockers.append("Cannot execute KILL_SESSION: No root blocker session verified in V$LOCKED_OBJECT.")

        # If action is PURGE_STAGING or RESET_REGISTRY, ensure no active workers are running
        if primary.remediation_action in ("PURGE_STAGING", "PURGE_STAGING_NO_VALIDATION", "RESET_REGISTRY"):
            active_workers = db_metrics.get("active_workers", 0)
            if active_workers > 0:
                can_proceed = False
                blockers.append(f"Cannot execute {primary.remediation_action}: {active_workers} collection workers are currently active.")

        return DiagnosticFinding(
            primary_diagnosis=primary,
            ranked_hypotheses=ranked,
            supporting_log_lines=log_lines,
            supporting_sql_observations=sql_obs,
            unresolved_uncertainties=primary.missing_evidence,
            overall_confidence=primary.confidence_score,
            can_proceed_to_remediation=can_proceed,
            remediation_blockers=blockers,
        )
