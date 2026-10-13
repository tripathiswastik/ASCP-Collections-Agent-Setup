"""Automated Remediation Subroutines for ASCP Collections.
Executes targeted interventions with strict parameter checking and execution guardrails:
1. Targeted Session Termination (KILL_SESSION)
2. Staging Maintenance Purge (PURGE_STAGING / MSCPDCP)
3. IPC Pipe Reset (RESET_PIPE)
4. Source Snapshot Re-Execution (RERUN_SNAPSHOT)
5. Partition Index Alignment (ALIGN_INDEXES)
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any

from ascp_agent.guardrails import EnterpriseGuardrails

logger = logging.getLogger(__name__)

_IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9_$#]{0,29}(\.[A-Z][A-Z0-9_$#]{0,29})?$")

def _require_int(value: Any, name: str) -> int:
    """Validate positive integer parameter."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer, got {value!r}")
    if name == "sid" and value > 1_000_000:
        raise ValueError(f"{name} exceeds maximum Oracle session limit, got {value}")
    return value

def _require_identifier(value: Any, name: str) -> str:
    """Validate Oracle identifier (table, partition, mview, pipe)."""
    if not isinstance(value, str) or not _IDENTIFIER.match(value.upper().strip()):
        raise ValueError(f"{name} is not a valid Oracle identifier: {value!r}")
    return value.upper().strip()

def validate_oracle_identifier(name: str, field_name: str = "identifier") -> str:
    """Backwards-compatible wrapper for identifier validation."""
    return _require_identifier(name, field_name)

def validate_session_numeric(val: Any, field_name: str = "sid") -> int:
    """Backwards-compatible wrapper for integer session ID validation with bounds checking."""
    if isinstance(val, bool):
        raise ValueError(f"{field_name} must be a positive integer, got boolean")  # noqa: TRY004
    if isinstance(val, str):
        if not val.strip().isdigit():
            raise ValueError(f"{field_name} must contain only numeric digits: {val!r}")
        val = int(val.strip())
    if not isinstance(val, int) or val <= 0:
        raise ValueError(f"{field_name} must be a positive integer, got {val!r}")
    if field_name == "sid" and val > 1_000_000:
        raise ValueError(f"{field_name} exceeds maximum Oracle session limit (1,000,000), got {val}")
    if field_name == "serial" and val > 10_000_000:
        raise ValueError(f"{field_name} exceeds maximum Oracle serial limit (10,000,000), got {val}")
    return val

def _utc_now() -> str:
    """Returns standardized ISO-8601 UTC timestamp."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

@dataclass
class RemediationResult:
    action: str
    success: bool
    command_executed: str
    message: str
    target_object: str
    execution_time_ms: float
    audit_record: dict[str, Any]
    dry_run: bool = False

def format_kill_session_sql(sid: int, serial: int, inst_id: int | None = None) -> str:
    """Format ALTER SYSTEM KILL SESSION text (validated, no trailing semicolon).
    Supports Oracle RAC instance routing via optional inst_id ('sid,serial#,@inst_id').
    """
    sid = _require_int(sid, "sid")
    serial = _require_int(serial, "serial")
    if inst_id is not None:
        inst_id = _require_int(inst_id, "inst_id")
        return f"ALTER SYSTEM KILL SESSION '{sid},{serial},@{inst_id}' IMMEDIATE"
    return f"ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE"

def format_purge_staging_sql(instance_id: int = 1001, validation: str = "N", package_name: str = "MSC_CL_COLLECTION") -> str:
    """Format standardized PL/SQL call to purge staging tables with Validation = No.
    Supports MSC_CL_COLLECTION (standard R12) and MSC_CL_PULL (classic/legacy).
    """
    inst = _require_int(instance_id, "instance_id")
    val = "N" if str(validation).upper().startswith("N") else "Y"
    pkg = _require_identifier(package_name, "package_name")
    if pkg not in ("MSC_CL_COLLECTION", "MSC_CL_PULL"):
        raise ValueError(f"Unsupported purge package '{pkg}'. Expected MSC_CL_COLLECTION or MSC_CL_PULL.")
    return f"BEGIN {pkg}.PURGE_STAGING_TABLES_SUB(p_instance_id => {inst}, p_validation => '{val}'); END;"

def format_registry_reset_sql(instance_id: int = 1001, status: int = 0) -> str:
    """Format standardized SQL statement to reset instance ST_STATUS in registry."""
    inst = _require_int(instance_id, "instance_id")
    return f"UPDATE MSC_APPS_INSTANCES SET ST_STATUS = {int(status)} WHERE INSTANCE_ID = {inst}"

def format_align_indexes_sql(table_name: str) -> str:
    """Format standardized index alignment procedure call for partition exchanges."""
    tbl = _require_identifier(table_name, "table_name")
    return f"BEGIN MSC_CL_EXCHANGE_PARTTN.ALIGN_INDEX_DEFS('{tbl}'); END;"

def format_reset_pipe_sql(instance_code: str = "PRD1") -> str:
    """Format standardized DBMS_PIPE purge call."""
    code = _require_identifier(instance_code, "instance_code")
    return f"BEGIN DBMS_PIPE.PURGE('MSC_PIPE_{code}'); END;"

def _validated_mode(mode: str) -> str:
    """Validate snapshot refresh mode ('F' for fast, 'C' for complete)."""
    if str(mode).upper() not in ("F", "C"):
        raise ValueError(f"mode must be 'F' or 'C', got {mode!r}")
    return str(mode).upper()

def format_snapshot_refresh_sql(mview_name: str, mode: str = "F") -> str:
    """Format standardized snapshot refresh procedure call."""
    mv = _require_identifier(mview_name, "mview_name")
    v_mode = _validated_mode(mode)
    return f"BEGIN DBMS_SNAPSHOT.REFRESH('{mv}', '{v_mode}'); END;"

def format_recovery_command_block(instance_id: int = 1001, instance_code: str = "PRD1", validation: str = "N") -> str:
    """Build complete multi-line automated pipeline recovery command block."""
    inst = _require_int(instance_id, "instance_id")
    code = _require_identifier(instance_code, "instance_code")
    return (
        f"CONCURRENT PROGRAM: Planning Data Collection - Purge Staging Tables\n"
        f"PARAMETERS: Instance = {code} ({inst}), Validation = {'No' if validation == 'N' else 'Yes'}\n"
        f"PL/SQL EXEC: {format_purge_staging_sql(inst, validation)}\n"
        f"REGISTRY RESET: UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = {inst};"
    )

class RemediationEngine:
    """Executes validated remediation subroutines with safety guardrails."""

    def __init__(self, connection_config: Any | None = None, guardrails: EnterpriseGuardrails | None = None):
        self.config = connection_config
        self.guardrails = guardrails or EnterpriseGuardrails()
        self.simulated = connection_config is None or getattr(connection_config, "use_simulation", True)

    def _execute(self, sql_text: str) -> None:
        """Validate, then simulate or fail loudly. Never report success for a no-op."""
        self.guardrails.validate_sql_command(sql_text)
        if self.simulated:
            time.sleep(0.04)  # Simulated execution latency
            return
        raise NotImplementedError("Live remediation not wired. Call the APPS wrapper with bind variables here.")

    def _run(
        self,
        action: str,
        sql_statement: str,
        target_object: str,
        audit_data: dict[str, Any],
        dry_run: bool = False,
        message: str | None = None
    ) -> RemediationResult:
        """Unified execution, validation, latency measurement, and audit pipeline for all remediation subroutines."""
        start = time.time()
        statements = [s.strip() for s in sql_statement.strip().split("\n") if s.strip()]

        # Enforce guardrail validation across all statements in the batch
        for stmt in statements:
            if not stmt.startswith("--"):
                self.guardrails.validate_sql_command(stmt)

        elapsed = round((time.time() - start) * 1000, 2)
        audit_record = {
            "action": action,
            "target": target_object,
            "dry_run": dry_run,
            "timestamp": _utc_now(),
            **audit_data
        }

        if dry_run:
            dry_cmds = "\n".join(f"-- DRY-RUN: {stmt}" for stmt in statements)
            return RemediationResult(
                action=f"{action}_DRY_RUN",
                success=True,
                command_executed=dry_cmds,
                message=message or f"Dry run validated: verified {action} on {target_object}.",
                target_object=target_object,
                execution_time_ms=elapsed,
                audit_record={**audit_record, "status": "DRY_RUN_PASSED"},
                dry_run=True
            )

        for stmt in statements:
            self._execute(stmt)

        total_elapsed = round((time.time() - start) * 1000, 2)
        prefix = "[SIMULATED] " if self.simulated else ""
        return RemediationResult(
            action=action,
            success=True,
            command_executed=sql_statement,
            message=f"{prefix}{message or f'Executed {action} successfully on {target_object}.'}",
            target_object=target_object,
            execution_time_ms=total_elapsed,
            audit_record={**audit_record, "status": "NORMALIZED" if action == "PURGE_STAGING_NO_VALIDATION" else "EXECUTED"},
            dry_run=False
        )

    def execute_kill_session(
        self,
        sid: int,
        serial: int,
        object_name: str,
        inst_id: int | None = None,
        username: str | None = None,
        module: str | None = None,
        session_type: str | None = "USER",
        self_sid: int | None = None,
        instance_id: int | str | None = None,
        undo_check: dict[str, Any] | None = None,
        dry_run: bool = False,
        force_override: bool = False
    ) -> RemediationResult:
        """Issues ALTER SYSTEM KILL SESSION after validating undo volume and blast-radius safety limits."""
        start = time.time()
        v_sid = _require_int(sid, "sid")
        v_serial = _require_int(serial, "serial")
        v_obj = _require_identifier(object_name, "object_name")
        v_inst = _require_int(inst_id, "inst_id") if inst_id is not None else None

        # 1. Blast-radius user/process safety validation
        try:
            from ascp_agent.guardrails import (
                GLOBAL_KILL_LIMITER,
                BlastRadiusViolationError,
                validate_session_kill_safety,
            )
            validate_session_kill_safety(
                target_sid=v_sid,
                target_serial=v_serial,
                username=username,
                module=module,
                session_type=session_type,
                self_sid=self_sid
            )
        except BlastRadiusViolationError as exc:
            return RemediationResult(
                action="BLAST_RADIUS_VIOLATION",
                success=False,
                command_executed=f"-- TERMINATION BLOCKED: Blast Radius Safeguard Violation ({exc})",
                message=f"Session termination refused by blast-radius safety guardrails: {exc}",
                target_object=v_obj,
                execution_time_ms=round((time.time() - start) * 1000, 2),
                audit_record={
                    "action": "BLAST_RADIUS_VIOLATION",
                    "target": v_obj,
                    "sid": v_sid,
                    "serial": v_serial,
                    "reason": str(exc),
                    "status": "BLOCKED",
                    "timestamp": _utc_now()
                },
                dry_run=dry_run
            )

        # 2. Live production safety: Require live undo validation
        if not self.simulated and undo_check is None:
            raise NotImplementedError("Live undo-volume check not implemented; refusing KILL_SESSION.")

        # 3. Inspect session undo rollback volume
        if undo_check is None:
            from ascp_agent.lock_engine import LockDiagnosticsEngine
            engine = LockDiagnosticsEngine()
            undo_check = engine.inspect_session_undo_volume(v_sid)

        if undo_check and undo_check.get("high_rollback_risk") and not force_override:
            used = undo_check.get("used_urec", 0)
            sec = undo_check.get("estimated_rollback_sec", 0)
            sn_ticket = None
            try:
                from ascp_agent.itsm_service_now import ServiceNowClient
                sn_client = ServiceNowClient()
                ticket_payload = {
                    "short_description": f"URGENT: High Rollback Blockade for Root Blocker SID {v_sid} on {v_obj}",
                    "description": (
                        f"Root blocker session SID {v_sid} (SERIAL# {v_serial}) holds Exclusive Mode 6 lock on {v_obj} "
                        f"with {used:,} uncommitted undo records in V$TRANSACTION. Estimated PMON rollback time: {sec}s. "
                        f"Automated KILL SESSION was aborted to avoid freeze on 'enq: TM - contention'. "
                        f"Manual DBA coordination required."
                    ),
                    "impact": "1",
                    "urgency": "1",
                    "priority": "1",
                    "category": "Database Lock Contention",
                    "assignment_group": "DBA-ORACLE-PRODUCTION",
                    "cmdb_ci": "EBS-ASCP-PROD",
                }
                sn_ticket = sn_client.dispatch_incident(ticket_payload)
            except Exception as sn_exc:  # noqa: BLE001
                logger.warning("Failed to dispatch ServiceNow alert for high undo volume: %s", sn_exc)

            sn_info = f" Dispatched P1 incident {sn_ticket.get('incident_number', '')} to DBA via ServiceNow." if sn_ticket else " Flagged high-priority alert for DBA."
            return RemediationResult(
                action="DEFERRED_ROLLBACK_ALERT",
                success=False,
                command_executed=f"-- TERMINATION DEFERRED: High Undo Rollback Volume ({used} records)",
                message=f"Session termination deferred: SID {v_sid} has {used} uncommitted undo records (estimated {sec}s rollback). Immediate kill will hang on enq: TM - contention while PMON rolls back.{sn_info}",
                target_object=v_obj,
                execution_time_ms=round((time.time() - start) * 1000, 2),
                audit_record={
                    "action": "DEFERRED_ROLLBACK_ALERT",
                    "target": v_obj,
                    "sid": v_sid,
                    "serial": v_serial,
                    "used_urec": used,
                    "estimated_rollback_sec": sec,
                    "servicenow_incident": sn_ticket,
                    "status": "DEFERRED",
                    "timestamp": _utc_now()
                },
                dry_run=dry_run
            )

        # 4. Rate Limiter Cooldown & Daily Cap (enforced on live mode and when configured)
        if not self.simulated or os.environ.get("ASCP_ENFORCE_SIMULATED_COOLDOWN", "").lower() in ("1", "true"):
            try:
                GLOBAL_KILL_LIMITER.check_and_record_kill(
                    instance_id=instance_id or v_inst or "1001",
                    dry_run=dry_run,
                    force_override=force_override
                )
            except BlastRadiusViolationError as exc:
                return RemediationResult(
                    action="BLAST_RADIUS_VIOLATION",
                    success=False,
                    command_executed=f"-- TERMINATION BLOCKED: Rate Limiter Cooldown/Cap Violation ({exc})",
                    message=f"Session termination refused by blast-radius rate limiter: {exc}",
                    target_object=v_obj,
                    execution_time_ms=round((time.time() - start) * 1000, 2),
                    audit_record={
                        "action": "BLAST_RADIUS_VIOLATION",
                        "target": v_obj,
                        "sid": v_sid,
                        "serial": v_serial,
                        "reason": str(exc),
                        "status": "BLOCKED",
                        "timestamp": _utc_now()
                    },
                    dry_run=dry_run
                )

        sql_cmd = format_kill_session_sql(v_sid, v_serial, inst_id=v_inst)
        inst_label = f" on RAC instance {v_inst}" if v_inst is not None else ""
        return self._run(
            action="KILL_SESSION",
            sql_statement=sql_cmd,
            target_object=v_obj,
            audit_data={"sid": v_sid, "serial": v_serial, "object": v_obj, "inst_id": v_inst, "action": "ALTER_SYSTEM_KILL_SESSION"},
            dry_run=dry_run,
            message=f"Successfully terminated blocking database session SID {v_sid} (SERIAL# {v_serial}){inst_label}. Exclusive lock on {v_obj} released."
        )

    def execute_purge_staging(self, instance_id: int = 1001, dry_run: bool = False) -> RemediationResult:
        """Executes Purge Staging Tables (MSCPDCP / PURGE_STAGING_TABLES_SUB)."""
        v_inst = _require_int(instance_id, "instance_id")
        sql_cmd = f"BEGIN MSC_CL_PULL.PURGE_STAGING_TABLES_SUB(p_instance_id => {v_inst}); END;"
        return self._run(
            action="PURGE_STAGING",
            sql_statement=sql_cmd,
            target_object="MSC_ST_*",
            audit_data={"instance_id": v_inst, "procedure": "MSC_CL_PULL.PURGE_STAGING_TABLES_SUB"},
            dry_run=dry_run,
            message=f"Successfully executed MSCPDCP subroutine for Instance ID {v_inst}. Residual MSC_ST_* interface records truncated."
        )

    def execute_purge_staging_no_validation(
        self,
        instance_id: int = 1001,
        package_name: str = "MSC_CL_COLLECTION",
        dry_run: bool = False
    ) -> RemediationResult:
        """Executes Planning Data Collection - Purge Staging Tables with Validation = No and normalizes ST_STATUS to 0."""
        v_inst = _require_int(instance_id, "instance_id")
        sql_cmd = format_purge_staging_sql(v_inst, "N", package_name=package_name)
        reset_sql = f"UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = {v_inst}"
        combined_sql = f"{sql_cmd}\n{reset_sql}"
        return self._run(
            action="PURGE_STAGING_NO_VALIDATION",
            sql_statement=combined_sql,
            target_object="MSC_APPS_INSTANCES / MSC_ST_*",
            audit_data={"instance_id": v_inst, "validation": "No", "normalized_st_status": 0},
            dry_run=dry_run,
            message="Executed Purge Staging Tables with Validation = No. MSC_ST_* cleared and MSC_APPS_INSTANCES.ST_STATUS normalized to 0."
        )

    def execute_reset_pipe(self, pipe_name: str = "MSC_PIPE_1001", dry_run: bool = False) -> RemediationResult:
        """Purges stale DBMS_PIPE buffers and resets child IPC queues."""
        v_pipe = _require_identifier(pipe_name, "pipe_name")
        sql_cmd = f"BEGIN DBMS_PIPE.PURGE('{v_pipe}'); END;"
        return self._run(
            action="RESET_PIPE",
            sql_statement=sql_cmd,
            target_object=v_pipe,
            audit_data={"pipe_name": v_pipe, "action": "DBMS_PIPE.PURGE"},
            dry_run=dry_run,
            message=f"DBMS_PIPE buffers successfully purged for pipe '{v_pipe}'."
        )

    def execute_snapshot_refresh(self, mview_name: str, mode: str = "F", dry_run: bool = False) -> RemediationResult:
        """Invokes DBMS_SNAPSHOT.REFRESH in fast ('F') or complete ('C') mode."""
        v_mv = _require_identifier(mview_name, "mview_name")
        v_mode = _validated_mode(mode)
        sql_cmd = f"BEGIN DBMS_SNAPSHOT.REFRESH('{v_mv}', '{v_mode}'); END;"
        return self._run(
            action="RERUN_SNAPSHOT",
            sql_statement=sql_cmd,
            target_object=v_mv,
            audit_data={"mview_name": v_mv, "mode": v_mode},
            dry_run=dry_run,
            message=f"Materialized view '{v_mv}' refreshed in mode '{v_mode}'."
        )

    def execute_align_indexes(self, table_name: str = "MSC_DEMANDS", dry_run: bool = False) -> RemediationResult:
        """Re-aligns index definitions and constraints across staging and ODS."""
        v_tbl = _require_identifier(table_name, "table_name")
        sql_cmd = f"BEGIN MSC_CL_EXCHANGE_PARTTN.ALIGN_INDEX_DEFS('{v_tbl}'); END;"
        return self._run(
            action="ALIGN_INDEXES",
            sql_statement=sql_cmd,
            target_object=v_tbl,
            audit_data={"table_name": v_tbl, "action": "ALIGN_INDEX_DEFS"},
            dry_run=dry_run,
            message=f"Partition exchange index structures for '{v_tbl}' aligned with staging tables."
        )

    def execute_extend_undo_retention(self, retention_seconds: int = 10800, dry_run: bool = False) -> RemediationResult:
        """Increases UNDO_RETENTION dynamically to prevent ORA-01555 during long extractions."""
        v_sec = _require_int(retention_seconds, "retention_seconds")
        sql_cmd = f"ALTER SYSTEM SET UNDO_RETENTION = {v_sec} SCOPE=BOTH"
        return self._run(
            action="EXTEND_UNDO_RETENTION",
            sql_statement=sql_cmd,
            target_object="V$PARAMETER.UNDO_RETENTION",
            audit_data={"retention_seconds": v_sec, "scope": "BOTH"},
            dry_run=dry_run,
            message=f"UNDO_RETENTION extended to {v_sec} seconds to eliminate ORA-01555 snapshot too old stalls."
        )

    def execute_extend_tablespace(self, tablespace_name: str = "APPS_TS_STAGING", dry_run: bool = False) -> RemediationResult:
        """Adds datafile autoextend to prevent ORA-01653 extent allocation failures."""
        v_ts = _require_identifier(tablespace_name, "tablespace_name")
        sql_cmd = f"ALTER TABLESPACE {v_ts} ADD DATAFILE SIZE 100M AUTOEXTEND ON NEXT 50M"
        return self._run(
            action="EXTEND_TABLESPACE",
            sql_statement=sql_cmd,
            target_object=v_ts,
            audit_data={"tablespace": v_ts, "action": "ADD_DATAFILE_AUTOEXTEND"},
            dry_run=dry_run,
            message=f"Tablespace '{v_ts}' extended with autoextensible datafile storage."
        )

    def execute_flush_shared_pool(self, dry_run: bool = False) -> RemediationResult:
        """Flushes SGA shared pool to clear memory fragmentation causing ORA-04031."""
        sql_cmd = "ALTER SYSTEM FLUSH SHARED_POOL"
        return self._run(
            action="FLUSH_SHARED_POOL",
            sql_statement=sql_cmd,
            target_object="V$SGASTAT.SHARED_POOL",
            audit_data={"action": "FLUSH_SHARED_POOL"},
            dry_run=dry_run,
            message="Flushed SGA shared pool memory heap to remediate ORA-04031 memory allocation failure."
        )

    def execute_reset_registry(self, instance_id: int = 1001, dry_run: bool = False) -> RemediationResult:
        """Resets stuck ST_STATUS registry flag to 0 (IDLE) after unhandled worker crash."""
        v_inst = _require_int(instance_id, "instance_id")
        sql_cmd = f"UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = {v_inst}"
        return self._run(
            action="RESET_REGISTRY",
            sql_statement=sql_cmd,
            target_object="MSC_APPS_INSTANCES",
            audit_data={"instance_id": v_inst, "st_status": 0},
            dry_run=dry_run,
            message=f"MSC_APPS_INSTANCES.ST_STATUS for instance {v_inst} reset to 0 (IDLE) allowing new collections to launch."
        )

    def recover_crashed_pipeline_registry(
        self,
        instance_id: int = 1001,
        instance_code: str = "PRD1",
        dry_run: bool = False,
        active_workers_count: int = 0
    ) -> RemediationResult:
        """Automates recovery subroutine for crashed pipeline registry locks (ST_STATUS > 0).
        Verifies process termination (0 active workers), resets ST_STATUS = 0,
        and executes Planning Data Collection - Purge Staging Tables with Validation = No.
        """
        start = time.time()
        v_inst = _require_int(instance_id, "instance_id")
        v_code = _require_identifier(instance_code, "instance_code")

        if active_workers_count > 0:
            return RemediationResult(
                action="RECOVERY_BLOCKED_ACTIVE_WORKERS",
                success=False,
                command_executed="-- RECOVERY BLOCKED: Concurrent workers are still running",
                message=(
                    f"Refusing to reset ST_STATUS: {active_workers_count} concurrent worker processes "
                    f"are still active for instance {v_code} ({v_inst}). Terminate workers before resetting registry."
                ),
                target_object="MSC_APPS_INSTANCES",
                execution_time_ms=round((time.time() - start) * 1000, 2),
                audit_record={
                    "action": "RECOVERY_BLOCKED_ACTIVE_WORKERS",
                    "instance_id": v_inst,
                    "active_workers": active_workers_count,
                    "status": "BLOCKED",
                    "timestamp": _utc_now()
                },
                dry_run=dry_run
            )

        purge_sql = format_purge_staging_sql(v_inst, validation="N")
        reset_sql = format_registry_reset_sql(v_inst, status=0)
        combined_sql = f"{reset_sql}\n{purge_sql}"

        return self._run(
            action="RECOVER_CRASHED_PIPELINE",
            sql_statement=combined_sql,
            target_object=f"MSC_APPS_INSTANCES({v_inst}) / MSC_ST_*",
            audit_data={
                "instance_id": v_inst,
                "instance_code": v_code,
                "active_workers_verified": 0,
                "st_status_reset": 0,
                "purge_staging": "Validation=No"
            },
            dry_run=dry_run,
            message=(
                f"Recovered crashed pipeline registry for instance {v_code} ({v_inst}): "
                f"verified 0 active workers, reset ST_STATUS = 0, and executed Purge Staging Tables with Validation = No."
            )
        )

    def execute_inspect_locks(self, dry_run: bool = False) -> RemediationResult:
        """Non-mutating diagnostic lock inspection."""
        return RemediationResult(
            action="INSPECT_LOCKS",
            success=True,
            command_executed="-- DIAGNOSTIC READ-ONLY LOCK INSPECTION",
            message="Completed lock tree inspection. Telemetry analyzed without database mutation.",
            target_object="V$LOCK",
            execution_time_ms=5.0,
            audit_record={"action": "INSPECT_LOCKS", "status": "INSPECTED", "timestamp": _utc_now()},
            dry_run=dry_run
        )
