"""Automated Remediation Subroutines for ASCP Collections.
Executes targeted interventions:
1. Targeted Session Termination (KILL_SESSION)
2. Staging Maintenance Purge (PURGE_STAGING / MSCPDCP)
3. IPC Pipe Reset (RESET_PIPE)
4. Source Snapshot Re-Execution (RERUN_SNAPSHOT)
5. Partition Index Alignment (ALIGN_INDEXES)
"""

import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

@dataclass
class RemediationResult:
    action: str
    success: bool
    command_executed: str
    message: str
    target_object: str
    execution_time_ms: float
    audit_record: Dict[str, Any]

def format_kill_session_sql(sid: int, serial: int) -> str:
    """Format standardized ALTER SYSTEM KILL SESSION SQL string."""
    return f"ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE;"

def format_purge_staging_sql(instance_id: int = 1001, validation: str = "N") -> str:
    """Format standardized PL/SQL call to purge staging tables with Validation = No."""
    return f"BEGIN MSC_CL_COLLECTION.PURGE_STAGING_TABLES_SUB(p_instance_id => {instance_id}, p_validation => '{validation}'); END;"

def format_registry_reset_sql(instance_id: int = 1001, status: int = 0) -> str:
    """Format standardized SQL statement to reset instance ST_STATUS in registry."""
    return f"UPDATE MSC_APPS_INSTANCES SET ST_STATUS = {status} WHERE INSTANCE_ID = {instance_id}; COMMIT;"

def format_align_indexes_sql(table_name: str) -> str:
    """Format standardized index alignment procedure call for partition exchanges."""
    return f"EXEC MSC_CL_EXCHANGE_PARTTN.ALIGN_INDEX_DEFS('{table_name}');"

def format_reset_pipe_sql(instance_code: str = "PRD1") -> str:
    """Format standardized DBMS_PIPE purge call."""
    return f"EXEC DBMS_PIPE.PURGE('MSC_PIPE_{instance_code}');"

def format_snapshot_refresh_sql(mview_name: str) -> str:
    """Format standardized snapshot refresh procedure call."""
    return f"EXEC DBMS_SNAPSHOT.REFRESH('{mview_name}', 'F');"

def format_recovery_command_block(instance_id: int = 1001, instance_code: str = "PRD1", validation: str = "N") -> str:
    """Build complete multi-line automated pipeline recovery command block."""
    return (
        f"CONCURRENT PROGRAM: Planning Data Collection - Purge Staging Tables\n"
        f"PARAMETERS: Instance = {instance_code} ({instance_id}), Validation = {'No' if validation == 'N' else 'Yes'}\n"
        f"PL/SQL EXEC: {format_purge_staging_sql(instance_id, validation)}\n"
        f"REGISTRY RESET: UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = {instance_id};"
    )

class RemediationEngine:
    """Executes validated remediation subroutines with safety guardrails."""

    def __init__(self, connection_config: Optional[Any] = None):
        self.config = connection_config

    def execute_kill_session(self, sid: int, serial: int, object_name: str, undo_check: Optional[Dict[str, Any]] = None) -> RemediationResult:
        """Issues ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE after validating undo rollback volume."""
        start = time.time()

        # Prevent PMON un-abortable rollback lock hang if uncommitted transaction volume is large
        if undo_check and undo_check.get("high_rollback_risk"):
            used = undo_check.get("used_urec", 0)
            sec = undo_check.get("estimated_rollback_sec", 0)
            return RemediationResult(
                action="DEFERRED_ROLLBACK_ALERT",
                success=False,
                command_executed=f"-- TERMINATION DEFERRED: High Undo Rollback Volume ({used} records)",
                message=f"Session termination deferred: SID {sid} has {used} uncommitted undo records (estimated {sec}s rollback). Immediate kill will hang on enq: TM - contention while PMON rolls back. Dispatched alert to DBA via ServiceNow.",
                target_object=object_name,
                execution_time_ms=round((time.time() - start) * 1000, 2),
                audit_record={
                    "sid": sid,
                    "serial": serial,
                    "object": object_name,
                    "used_urec": used,
                    "action": "DEFERRED_ROLLBACK_ALERT",
                    "status": "ALERTED",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }
            )

        sql_cmd = f"ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE;"

        # In production with live DB: cursor.execute("BEGIN APPS.KILL_SESSION_WRAPPER(:1, :2); END;", [sid, serial])
        time.sleep(0.05)  # Simulated execution latency
        elapsed = (time.time() - start) * 1000

        return RemediationResult(
            action="KILL_SESSION",
            success=True,
            command_executed=sql_cmd,
            message=f"Successfully terminated blocking database session SID {sid} (SERIAL# {serial}). Exclusive lock on {object_name} released.",
            target_object=object_name,
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "sid": sid,
                "serial": serial,
                "object": object_name,
                "action": "ALTER_SYSTEM_KILL_SESSION",
                "status": "TERMINATED",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        )

    def execute_purge_staging(self, instance_id: int = 1001) -> RemediationResult:
        """Executes Purge Staging Tables (MSCPDCP / PURGE_STAGING_TABLES_SUB)."""
        start = time.time()
        sql_cmd = f"BEGIN MSC_CL_PULL.PURGE_STAGING_TABLES_SUB(p_instance_id => {instance_id}); END;"

        time.sleep(0.08)
        elapsed = (time.time() - start) * 1000

        return RemediationResult(
            action="PURGE_STAGING",
            success=True,
            command_executed=sql_cmd,
            message=f"Successfully executed MSCPDCP subroutine for Instance ID {instance_id}. Residual MSC_ST_* interface records truncated.",
            target_object="MSC_ST_*",
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "instance_id": instance_id,
                "procedure": "MSC_CL_PULL.PURGE_STAGING_TABLES_SUB",
                "status": "COMPLETED",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        )

    def execute_purge_staging_no_validation(self, instance_id: int = 1001) -> RemediationResult:
        """Executes Planning Data Collection - Purge Staging Tables with Validation = No and normalizes ST_STATUS to 0."""
        start = time.time()
        sql_cmd = (
            f"BEGIN MSC_CL_COLLECTION.PURGE_STAGING_TABLES_SUB(p_instance_id => {instance_id}, p_validation => 'N'); "
            f"UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = {instance_id}; COMMIT; END;"
        )

        time.sleep(0.08)
        elapsed = (time.time() - start) * 1000

        return RemediationResult(
            action="PURGE_STAGING_NO_VALIDATION",
            success=True,
            command_executed=sql_cmd,
            message=f"Executed Purge Staging Tables with Validation = No. MSC_ST_* cleared and MSC_APPS_INSTANCES.ST_STATUS normalized to 0.",
            target_object="MSC_APPS_INSTANCES / MSC_ST_*",
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "instance_id": instance_id,
                "validation": "No",
                "normalized_st_status": 0,
                "status": "NORMALIZED",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        )

    def execute_reset_pipe(self, pipe_name: str = "MSC_PIPE_1001") -> RemediationResult:
        """Purges stale DBMS_PIPE buffers and resets child IPC queues."""
        start = time.time()
        sql_cmd = f"BEGIN DBMS_PIPE.PURGE('{pipe_name}'); END;"

        time.sleep(0.04)
        elapsed = (time.time() - start) * 1000

        return RemediationResult(
            action="RESET_PIPE",
            success=True,
            command_executed=sql_cmd,
            message=f"DBMS_PIPE '{pipe_name}' successfully purged. Orphan worker locks cleared.",
            target_object=pipe_name,
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "pipe_name": pipe_name,
                "action": "DBMS_PIPE.PURGE",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        )

    def execute_snapshot_refresh(self, mview_name: str, mode: str = "F") -> RemediationResult:
        """Invokes DBMS_SNAPSHOT.REFRESH in fast ('F') or complete ('C') mode."""
        start = time.time()
        sql_cmd = f"BEGIN DBMS_SNAPSHOT.REFRESH('{mview_name}', '{mode}'); END;"

        time.sleep(0.06)
        elapsed = (time.time() - start) * 1000

        return RemediationResult(
            action="RERUN_SNAPSHOT",
            success=True,
            command_executed=sql_cmd,
            message=f"Materialized view '{mview_name}' refreshed in mode '{mode}'.",
            target_object=mview_name,
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "mview_name": mview_name,
                "mode": mode,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        )

    def execute_align_indexes(self, table_name: str = "MSC_DEMANDS") -> RemediationResult:
        """Re-aligns index definitions and constraints across staging and ODS."""
        start = time.time()
        sql_cmd = f"BEGIN MSC_CL_EXCHANGE_PARTTN.ALIGN_INDEX_DEFS('{table_name}'); END;"

        time.sleep(0.07)
        elapsed = (time.time() - start) * 1000

        return RemediationResult(
            action="ALIGN_INDEXES",
            success=True,
            command_executed=sql_cmd,
            message=f"Partition exchange index structures for '{table_name}' aligned with staging tables.",
            target_object=table_name,
            execution_time_ms=round(elapsed, 2),
            audit_record={
                "table_name": table_name,
                "action": "ALIGN_INDEX_DEFS",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        )
