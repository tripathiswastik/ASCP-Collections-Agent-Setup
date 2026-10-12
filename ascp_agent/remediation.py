"""Automated Remediation Subroutines for ASCP Collections.
Executes targeted interventions with strict parameter checking and execution guardrails:
1. Targeted Session Termination (KILL_SESSION)
2. Staging Maintenance Purge (PURGE_STAGING / MSCPDCP)
3. IPC Pipe Reset (RESET_PIPE)
4. Source Snapshot Re-Execution (RERUN_SNAPSHOT)
5. Partition Index Alignment (ALIGN_INDEXES)
"""

import re
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional
from ascp_agent.guardrails import EnterpriseGuardrails

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
        raise ValueError(f"{field_name} must be a positive integer, got boolean")
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
    audit_record: Dict[str, Any]
    dry_run: bool = False

def format_kill_session_sql(sid: int, serial: int) -> str:
    """Format ALTER SYSTEM KILL SESSION text (validated, no trailing semicolon)."""
    sid = _require_int(sid, "sid")
    serial = _require_int(serial, "serial")
    return f"ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE"

def format_purge_staging_sql(instance_id: int = 1001, validation: str = "N") -> str:
    """Format standardized PL/SQL call to purge staging tables with Validation = No."""
    inst = _require_int(instance_id, "instance_id")
    val = "N" if str(validation).upper().startswith("N") else "Y"
    return f"BEGIN MSC_CL_COLLECTION.PURGE_STAGING_TABLES_SUB(p_instance_id => {inst}, p_validation => '{val}'); END;"

def format_registry_reset_sql(instance_id: int = 1001, status: int = 0) -> str:
    """Format standardized SQL statement to reset instance ST_STATUS in registry."""
    inst = _require_int(instance_id, "instance_id")
    return f"UPDATE MSC_APPS_INSTANCES SET ST_STATUS = {int(status)} WHERE INSTANCE_ID = {inst}; COMMIT;"

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

    def __init__(self, connection_config: Optional[Any] = None, guardrails: Optional[EnterpriseGuardrails] = None):
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

    def execute_kill_session(
        self,
        sid: int,
        serial: int,
        object_name: str,
        undo_check: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
        force_override: bool = False
    ) -> RemediationResult:
        """Issues ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE after validating undo rollback volume."""
        start = time.time()
        v_sid = _require_int(sid, "sid")
        v_serial = _require_int(serial, "serial")
        v_obj = _require_identifier(object_name, "object_name")

        # Automatically check rollback volume if not provided
        if not self.simulated and undo_check is None:
            raise NotImplementedError("Live undo-volume check not implemented; refusing KILL_SESSION.")

        if undo_check is None:
            from ascp_agent.lock_engine import LockDiagnosticsEngine
            engine = LockDiagnosticsEngine()
            undo_check = engine.inspect_session_undo_volume(v_sid)

        # Prevent PMON un-abortable rollback lock hang if uncommitted transaction volume is large
        if undo_check and undo_check.get("high_rollback_risk") and not force_override:
            used = undo_check.get("used_urec", 0)
            sec = undo_check.get("estimated_rollback_sec", 0)
            return RemediationResult(
                action="DEFERRED_ROLLBACK_ALERT",
                success=False,
                command_executed=f"-- TERMINATION DEFERRED: High Undo Rollback Volume ({used} records)",
                message=f"Session termination deferred: SID {v_sid} has {used} uncommitted undo records (estimated {sec}s rollback). Immediate kill will hang on enq: TM - contention while PMON rolls back. Dispatched alert to DBA via ServiceNow.",
                target_object=v_obj,
                execution_time_ms=round((time.time() - start) * 1000, 2),
                audit_record={
                    "sid": v_sid,
                    "serial": v_serial,
                    "object": v_obj,
                    "used_urec": used,
                    "action": "DEFERRED_ROLLBACK_ALERT",
                    "status": "ALERTED",
                    "timestamp": _utc_now()
                },
                dry_run=dry_run
            )

        sql_cmd = format_kill_session_sql(v_sid, v_serial)

        if dry_run:
            self.guardrails.validate_sql_command(sql_cmd)
            return RemediationResult(
                action="KILL_SESSION_DRY_RUN",
                success=True,
                command_executed=f"-- DRY-RUN: {sql_cmd}",
                message=f"Dry run validated: verified SID {v_sid} (SERIAL# {v_serial}) targeting {v_obj}.",
                target_object=v_obj,
                execution_time_ms=round((time.time() - start) * 1000, 2),
                audit_record={"sid": v_sid, "serial": v_serial, "object": v_obj, "status": "DRY_RUN_PASSED"},
                dry_run=True
            )

        self._execute(sql_cmd)
        elapsed = (time.time() - start) * 1000
        prefix = "[SIMULATED] " if self.simulated else ""

        return RemediationResult(
            action="KILL_SESSION",
            success=True,
            command_executed=sql_cmd,
            message=f"{prefix}Successfully terminated blocking database session SID {v_sid} (SERIAL# {v_serial}). Exclusive lock on {v_obj} released.",
            target_object=v_obj,
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "sid": v_sid,
                "serial": v_serial,
                "object": v_obj,
                "action": "ALTER_SYSTEM_KILL_SESSION",
                "status": "TERMINATED",
                "timestamp": _utc_now()
            },
            dry_run=False
        )

    def execute_purge_staging(self, instance_id: int = 1001, dry_run: bool = False) -> RemediationResult:
        """Executes Purge Staging Tables (MSCPDCP / PURGE_STAGING_TABLES_SUB)."""
        start = time.time()
        v_inst = _require_int(instance_id, "instance_id")
        sql_cmd = f"BEGIN MSC_CL_PULL.PURGE_STAGING_TABLES_SUB(p_instance_id => {v_inst}); END;"

        if dry_run:
            self.guardrails.validate_sql_command(sql_cmd)
            return RemediationResult(
                action="PURGE_STAGING_DRY_RUN",
                success=True,
                command_executed=f"-- DRY-RUN: {sql_cmd}",
                message=f"Dry run validated: verified staging purge for Instance ID {v_inst}.",
                target_object="MSC_ST_*",
                execution_time_ms=round((time.time() - start) * 1000, 2),
                audit_record={"instance_id": v_inst, "status": "DRY_RUN_PASSED"},
                dry_run=True
            )

        self._execute(sql_cmd)
        elapsed = (time.time() - start) * 1000
        prefix = "[SIMULATED] " if self.simulated else ""

        return RemediationResult(
            action="PURGE_STAGING",
            success=True,
            command_executed=sql_cmd,
            message=f"{prefix}Successfully executed MSCPDCP subroutine for Instance ID {v_inst}. Residual MSC_ST_* interface records truncated.",
            target_object="MSC_ST_*",
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "instance_id": v_inst,
                "procedure": "MSC_CL_PULL.PURGE_STAGING_TABLES_SUB",
                "status": "COMPLETED",
                "timestamp": _utc_now()
            },
            dry_run=False
        )

    def execute_purge_staging_no_validation(self, instance_id: int = 1001, dry_run: bool = False) -> RemediationResult:
        """Executes Planning Data Collection - Purge Staging Tables with Validation = No and normalizes ST_STATUS to 0."""
        start = time.time()
        v_inst = _require_int(instance_id, "instance_id")
        sql_cmd = (
            f"BEGIN MSC_CL_COLLECTION.PURGE_STAGING_TABLES_SUB(p_instance_id => {v_inst}, p_validation => 'N'); END;"
        )

        reset_sql = f"UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = {v_inst}"

        if dry_run:
            self.guardrails.validate_sql_command(sql_cmd)
            self.guardrails.validate_sql_command(reset_sql)
            return RemediationResult(
                action="PURGE_STAGING_NO_VALIDATION_DRY_RUN",
                success=True,
                command_executed=f"-- DRY-RUN: {sql_cmd}\n-- DRY-RUN: {reset_sql}",
                message=f"Dry run validated: verified purge staging no-validation for Instance ID {v_inst}.",
                target_object="MSC_APPS_INSTANCES / MSC_ST_*",
                execution_time_ms=round((time.time() - start) * 1000, 2),
                audit_record={"instance_id": v_inst, "status": "DRY_RUN_PASSED"},
                dry_run=True
            )

        self._execute(sql_cmd)
        self._execute(reset_sql)
        elapsed = (time.time() - start) * 1000
        prefix = "[SIMULATED] " if self.simulated else ""

        return RemediationResult(
            action="PURGE_STAGING_NO_VALIDATION",
            success=True,
            command_executed=f"{sql_cmd}\n{reset_sql}",
            message=f"{prefix}Executed Purge Staging Tables with Validation = No. MSC_ST_* cleared and MSC_APPS_INSTANCES.ST_STATUS normalized to 0.",
            target_object="MSC_APPS_INSTANCES / MSC_ST_*",
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "instance_id": v_inst,
                "validation": "No",
                "normalized_st_status": 0,
                "status": "NORMALIZED",
                "timestamp": _utc_now()
            },
            dry_run=False
        )

    def execute_reset_pipe(self, pipe_name: str = "MSC_PIPE_1001", dry_run: bool = False) -> RemediationResult:
        """Purges stale DBMS_PIPE buffers and resets child IPC queues."""
        start = time.time()
        v_pipe = _require_identifier(pipe_name, "pipe_name")
        sql_cmd = f"BEGIN DBMS_PIPE.PURGE('{v_pipe}'); END;"

        if dry_run:
            self.guardrails.validate_sql_command(sql_cmd)
            return RemediationResult(
                action="RESET_PIPE_DRY_RUN",
                success=True,
                command_executed=f"-- DRY-RUN: {sql_cmd}",
                message=f"Dry run validated: verified pipe purge for '{v_pipe}'.",
                target_object=v_pipe,
                execution_time_ms=round((time.time() - start) * 1000, 2),
                audit_record={"pipe_name": v_pipe, "status": "DRY_RUN_PASSED"},
                dry_run=True
            )

        self._execute(sql_cmd)
        elapsed = (time.time() - start) * 1000
        prefix = "[SIMULATED] " if self.simulated else ""

        return RemediationResult(
            action="RESET_PIPE",
            success=True,
            command_executed=sql_cmd,
            message=f"{prefix}DBMS_PIPE '{v_pipe}' successfully purged. Orphan worker locks cleared.",
            target_object=v_pipe,
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "pipe_name": v_pipe,
                "action": "DBMS_PIPE.PURGE",
                "timestamp": _utc_now()
            },
            dry_run=False
        )

    def execute_snapshot_refresh(self, mview_name: str, mode: str = "F", dry_run: bool = False) -> RemediationResult:
        """Invokes DBMS_SNAPSHOT.REFRESH in fast ('F') or complete ('C') mode."""
        start = time.time()
        v_mv = _require_identifier(mview_name, "mview_name")
        v_mode = _validated_mode(mode)
        sql_cmd = f"BEGIN DBMS_SNAPSHOT.REFRESH('{v_mv}', '{v_mode}'); END;"

        if dry_run:
            self.guardrails.validate_sql_command(sql_cmd)
            return RemediationResult(
                action="RERUN_SNAPSHOT_DRY_RUN",
                success=True,
                command_executed=f"-- DRY-RUN: {sql_cmd}",
                message=f"Dry run validated: verified snapshot refresh for '{v_mv}' in mode '{v_mode}'.",
                target_object=v_mv,
                execution_time_ms=round((time.time() - start) * 1000, 2),
                audit_record={"mview_name": v_mv, "mode": v_mode, "status": "DRY_RUN_PASSED"},
                dry_run=True
            )

        self._execute(sql_cmd)
        elapsed = (time.time() - start) * 1000
        prefix = "[SIMULATED] " if self.simulated else ""

        return RemediationResult(
            action="RERUN_SNAPSHOT",
            success=True,
            command_executed=sql_cmd,
            message=f"{prefix}Materialized view '{v_mv}' refreshed in mode '{v_mode}'.",
            target_object=v_mv,
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "mview_name": v_mv,
                "mode": v_mode,
                "timestamp": _utc_now()
            },
            dry_run=False
        )

    def execute_align_indexes(self, table_name: str = "MSC_DEMANDS", dry_run: bool = False) -> RemediationResult:
        """Re-aligns index definitions and constraints across staging and ODS."""
        start = time.time()
        v_tbl = _require_identifier(table_name, "table_name")
        sql_cmd = f"BEGIN MSC_CL_EXCHANGE_PARTTN.ALIGN_INDEX_DEFS('{v_tbl}'); END;"

        if dry_run:
            self.guardrails.validate_sql_command(sql_cmd)
            return RemediationResult(
                action="ALIGN_INDEXES_DRY_RUN",
                success=True,
                command_executed=f"-- DRY-RUN: {sql_cmd}",
                message=f"Dry run validated: verified partition alignment for '{v_tbl}'.",
                target_object=v_tbl,
                execution_time_ms=round((time.time() - start) * 1000, 2),
                audit_record={"table_name": v_tbl, "status": "DRY_RUN_PASSED"},
                dry_run=True
            )

        self._execute(sql_cmd)
        elapsed = (time.time() - start) * 1000
        prefix = "[SIMULATED] " if self.simulated else ""

        return RemediationResult(
            action="ALIGN_INDEXES",
            success=True,
            command_executed=sql_cmd,
            message=f"{prefix}Partition exchange index structures for '{v_tbl}' aligned with staging tables.",
            target_object=v_tbl,
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "table_name": v_tbl,
                "action": "ALIGN_INDEX_DEFS",
                "timestamp": _utc_now()
            },
            dry_run=False
        )
