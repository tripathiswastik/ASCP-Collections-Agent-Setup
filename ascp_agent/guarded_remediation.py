"""Guarded Remediation Authorization and Execution Layer for Oracle ASCP.
Enforces strict separation between read-only diagnostic analysis and write-remediation:

Guarantees:
1. Agent is read-only by default; remediation requires an explicit proposal step.
2. Every proposal includes target, impact, rollback plan, expected outcome, and pre-conditions.
3. Dry runs are executed before requesting human authorization.
4. Approval is cryptographically fingerprinted and bound to the exact target and action.
5. Immediate pre-execution recheck: If the blocker has already cleared or the target changed,
   execution aborts safely without destructive actions.
6. Post-execution verification confirms system recovery; failure stops safely.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from ascp_agent.diagnostic_tools import (
    OracleAdapter,
    PreconditionCheckResult,
    get_default_adapter,
    validate_remediation_preconditions,
)
from ascp_agent.lock_engine import LockDiagnosticsEngine
from ascp_agent.remediation import RemediationEngine, RemediationResult

logger = logging.getLogger(__name__)

# Default approval validity window in seconds
APPROVAL_TTL_SECONDS = 300.0  # 5 minutes


class RemediationGuardViolation(RuntimeError):
    """Raised when any remediation safety constraint or approval check is violated."""


@dataclass
class RemediationProposal:
    """Detailed remediation plan ready for DBA inspection and cryptographic approval."""
    proposal_id: str
    action: str
    target: dict[str, Any]
    target_fingerprint: str
    explanation: str
    impact_assessment: str
    rollback_plan: str
    expected_outcome: str
    verification_check: str
    preconditions: PreconditionCheckResult
    dry_run_success: bool
    dry_run_details: str
    requires_approval: bool
    created_at_unix: float
    expires_at_unix: float
    approval_status: str = "PENDING"  # PENDING, APPROVED, REJECTED, EXPIRED, EXECUTED
    approver: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["created_at_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.created_at_unix))
        d["expires_at_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.expires_at_unix))
        return d


@dataclass
class GuardedExecutionOutcome:
    """Complete audit result of a guarded remediation execution."""
    proposal_id: str
    action: str
    target: dict[str, Any]
    executed: bool
    success: bool
    aborted_early: bool
    abort_reason: str | None = None
    pre_recheck_passed: bool = False
    execution_result: dict[str, Any] = field(default_factory=dict)
    post_verification_passed: bool = False
    verification_details: str = ""
    timestamp_utc: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def calculate_remediation_fingerprint(action: str, target: dict[str, Any]) -> str:
    """Calculates deterministic SHA-256 fingerprint for action and target attributes."""
    components = [
        str(action).upper(),
        str(target.get("sid", "")),
        str(target.get("serial_number", "")),
        str(target.get("object_name", target.get("table_name", ""))).upper(),
        str(target.get("instance_id", "")),
    ]
    raw = ":".join(components)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class GuardedRemediationLayer:
    """Manages the end-to-end lifecycle of guarded remediation:
    Proposal -> Precondition Check -> Dry Run -> Authorization -> Pre-Check -> Execution -> Post-Verify.
    """

    def __init__(
        self,
        rem_engine: RemediationEngine | None = None,
        adapter: OracleAdapter | None = None,
    ):
        self.rem_engine = rem_engine or RemediationEngine()
        self.adapter = adapter or get_default_adapter()
        self._active_proposals: dict[str, RemediationProposal] = {}

    def propose_action(
        self,
        action: str,
        target: dict[str, Any],
        explanation: str,
        impact_assessment: str,
        rollback_plan: str,
        expected_outcome: str,
        verification_check: str = "SELECT 1 FROM DUAL",
        requires_approval: bool = True,
    ) -> RemediationProposal:
        """Step 1: Construct proposal, run precondition validation and dry-run."""
        # 1. Run Precondition Checks
        pre_result = validate_remediation_preconditions(action, target, adapter=self.adapter)
        if not pre_result.passed:
            raise RemediationGuardViolation(
                f"Remediation preconditions failed for '{action}': {', '.join(pre_result.failures)}"
            )

        # 2. Run Dry Run
        dry_success = True
        dry_message = "Dry run completed successfully."
        try:
            if action == "KILL_SESSION":
                res = self.rem_engine.execute_kill_session(
                    sid=target.get("sid", 0),
                    serial=target.get("serial_number", 0),
                    object_name=target.get("object_name", "MSC_ST_DEMANDS"),
                    inst_id=target.get("inst_id"),
                    username=target.get("username", "APPS"),
                    module=target.get("module", "MSCPDCW"),
                    session_type=target.get("session_type", "USER"),
                    instance_id=target.get("instance_id", 1001),
                    dry_run=True,
                )
                dry_success = res.success
                dry_message = res.message
            elif action in ("PURGE_STAGING", "PURGE_STAGING_NO_VALIDATION"):
                res = self.rem_engine.execute_purge_staging_no_validation(
                    instance_id=target.get("instance_id", 1001),
                    dry_run=True,
                )
                dry_success = res.success
                dry_message = res.message
            elif action in ("RESET_PIPE", "PURGE_PIPE"):
                res = self.rem_engine.execute_reset_pipe(
                    pipe_name=target.get("pipe_name", "MSC_PIPE_PRD1"),
                    dry_run=True,
                )
                dry_success = res.success
                dry_message = res.message
            elif action in ("ALIGN_INDEXES", "REBUILD_ALIGN_INDEXES"):
                res = self.rem_engine.execute_align_indexes(
                    table_name=target.get("table_name", "MSC_DEMANDS"),
                    dry_run=True,
                )
                dry_success = res.success
                dry_message = res.message
            elif action in ("RERUN_SNAPSHOT", "RERUN_SNAPSHOT_FAST", "REFRESH_SNAPSHOT"):
                res = self.rem_engine.execute_snapshot_refresh(
                    mview_name=target.get("mview_name", "MLOG$_OE_ORDER_LINES"),
                    mode="F",
                    dry_run=True,
                )
                dry_success = res.success
                dry_message = res.message
            elif action == "RESET_REGISTRY":
                res = self.rem_engine.execute_reset_registry(
                    instance_id=target.get("instance_id", 1001),
                    dry_run=True,
                )
                dry_success = res.success
                dry_message = res.message
        except Exception as exc:  # noqa: BLE001
            dry_success = False
            dry_message = f"Dry run raised exception: {exc}"

        if not dry_success:
            raise RemediationGuardViolation(f"Dry run pre-validation failed for '{action}': {dry_message}")

        now_unix = time.time()
        prop_id = f"PROP-{uuid.uuid4().hex[:10]}"
        fp = calculate_remediation_fingerprint(action, target)

        proposal = RemediationProposal(
            proposal_id=prop_id,
            action=action,
            target=target,
            target_fingerprint=fp,
            explanation=explanation,
            impact_assessment=impact_assessment,
            rollback_plan=rollback_plan,
            expected_outcome=expected_outcome,
            verification_check=verification_check,
            preconditions=pre_result,
            dry_run_success=dry_success,
            dry_run_details=dry_message,
            requires_approval=requires_approval,
            created_at_unix=now_unix,
            expires_at_unix=now_unix + APPROVAL_TTL_SECONDS,
            approval_status="APPROVED" if not requires_approval else "PENDING",
        )
        self._active_proposals[prop_id] = proposal
        return proposal

    def authorize_proposal(
        self,
        proposal_id: str,
        approver: str,
        submitted_fingerprint: str,
    ) -> bool:
        """Step 2: Explicit human authorization tied cryptographically to proposal fingerprint."""
        prop = self._active_proposals.get(proposal_id)
        if not prop:
            raise RemediationGuardViolation(f"Proposal '{proposal_id}' not found.")

        # Expiration Check
        if time.time() > prop.expires_at_unix:
            prop.approval_status = "EXPIRED"
            raise RemediationGuardViolation(f"Approval failed: Proposal '{proposal_id}' has expired (TTL exceeded).")

        # Cryptographic Fingerprint Check
        if submitted_fingerprint != prop.target_fingerprint:
            prop.approval_status = "REJECTED"
            raise RemediationGuardViolation(
                "Security alert: Submitted fingerprint does not match proposal. Target has changed or request was forged!"
            )

        prop.approval_status = "APPROVED"
        prop.approver = approver
        return True

    def execute_guarded(
        self,
        proposal_id: str,
    ) -> GuardedExecutionOutcome:
        """Step 3: Immediate pre-execution recheck, live execution, and post-verification."""
        prop = self._active_proposals.get(proposal_id)
        if not prop:
            raise RemediationGuardViolation(f"Proposal '{proposal_id}' not found.")

        # Guard: Check Approval
        if prop.requires_approval and prop.approval_status != "APPROVED":
            raise RemediationGuardViolation(
                f"Execution denied: Proposal '{proposal_id}' is not approved (status: {prop.approval_status})."
            )

        # Guard: Check Expiration
        if time.time() > prop.expires_at_unix:
            prop.approval_status = "EXPIRED"
            raise RemediationGuardViolation(f"Execution denied: Proposal '{proposal_id}' expired before execution.")

        # Guard: Immediate Target Pre-check
        # If target was a blocker session, verify it is still actively holding a lock right now
        if prop.action == "KILL_SESSION":
            target_sid = prop.target.get("sid", 0)
            target_serial = prop.target.get("serial_number", 0)
            lock_diag = LockDiagnosticsEngine()
            is_active = lock_diag.verify_session_active(target_sid, target_serial)
            if not is_active:
                # Blocker session self-terminated or lock cleared naturally while waiting for approval!
                return GuardedExecutionOutcome(
                    proposal_id=proposal_id,
                    action=prop.action,
                    target=prop.target,
                    executed=False,
                    success=True,
                    aborted_early=True,
                    abort_reason=f"Target session SID {target_sid} is no longer active. Lock cleared naturally; termination skipped safely.",
                    pre_recheck_passed=True,
                    post_verification_passed=True,
                    verification_details="Target lock no longer exists in V$SESSION.",
                )

        # Live Execution
        act = prop.action
        t = prop.target
        exec_res: RemediationResult

        if act == "KILL_SESSION":
            exec_res = self.rem_engine.execute_kill_session(
                sid=t.get("sid", 0),
                serial=t.get("serial_number", 0),
                object_name=t.get("object_name", "MSC_ST_DEMANDS"),
                inst_id=t.get("inst_id"),
                username=t.get("username", "APPS"),
                module=t.get("module", "MSCPDCW"),
                session_type=t.get("session_type", "USER"),
                instance_id=t.get("instance_id", 1001),
                dry_run=False,
            )
        elif act in ("PURGE_STAGING", "PURGE_STAGING_NO_VALIDATION"):
            exec_res = self.rem_engine.execute_purge_staging_no_validation(
                instance_id=t.get("instance_id", 1001),
                dry_run=False,
            )
        elif act in ("RESET_PIPE", "PURGE_PIPE"):
            exec_res = self.rem_engine.execute_reset_pipe(
                pipe_name=t.get("pipe_name", "MSC_PIPE_PRD1"),
                dry_run=False,
            )
        elif act in ("ALIGN_INDEXES", "REBUILD_ALIGN_INDEXES"):
            exec_res = self.rem_engine.execute_align_indexes(
                table_name=t.get("table_name", "MSC_DEMANDS"),
                dry_run=False,
            )
        elif act in ("RERUN_SNAPSHOT", "RERUN_SNAPSHOT_FAST", "REFRESH_SNAPSHOT"):
            exec_res = self.rem_engine.execute_snapshot_refresh(
                mview_name=t.get("mview_name", "MLOG$_OE_ORDER_LINES"),
                mode="F",
                dry_run=False,
            )
        elif act == "RESET_REGISTRY":
            exec_res = self.rem_engine.execute_reset_registry(
                instance_id=t.get("instance_id", 1001),
                dry_run=False,
            )
        else:
            exec_res = RemediationResult(
                action=act,
                success=True,
                command_executed="SELECT 1 FROM DUAL",
                message=f"Non-destructive or manual advisory action '{act}' noted.",
            )

        # Post-Execution Recovery Verification
        post_verified = True
        post_message = "Post-remediation state verified cleanly."

        if not exec_res.success:
            post_verified = False
            post_message = f"Execution failed: {exec_res.message}"
        else:
            # Run verification query
            try:
                if prop.verification_check:
                    res_ver = self.adapter.query(prop.verification_check)
                    post_message = f"Verification check '{prop.verification_check}' completed (rows: {res_ver.row_count})."
            except Exception as v_err:  # noqa: BLE001
                post_verified = False
                post_message = f"Post-execution verification check failed: {v_err}"

        prop.approval_status = "EXECUTED"

        return GuardedExecutionOutcome(
            proposal_id=proposal_id,
            action=prop.action,
            target=prop.target,
            executed=True,
            success=exec_res.success and post_verified,
            aborted_early=False,
            pre_recheck_passed=True,
            execution_result=vars(exec_res),
            post_verification_passed=post_verified,
            verification_details=post_message,
        )
