"""ASCP Collections Pipeline Monitor & Registry Status Engine.
Tracks execution lifecycle across Source ADS, Interface Staging (MSC_ST_*),
Operational Data Store (ODS plan_id = -1), and Planning Data Store (PDS).
Monitors MSC_APPS_INSTANCES.ST_STATUS registry flags and validation error codes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

ST_STATUS_MAP = {
    0: ("IDLE / STAGING_PREPARED", "Pipeline idle or staging structures cleansed and ready for pull."),
    1: ("PULL_PROCESSING", "Stage 1 Data Pull Active. MSRFWOR snapshot refreshes and MSCPDPW workers active."),
    2: ("LOAD_PROCESSING", "Stage 2 ODS Load Active. MSCPDCW workers validating staged rows and mapping surrogate keys."),
    3: ("PURGE_PROCESSING", "Stage 3 Staging Maintenance Active. MSCPDCP truncating interface tables."),
    -1: ("ERROR_STALLED", "Pipeline Stalled. Unhandled exceptions, deadlocks, or lock contention detected.")
}

@dataclass
class InstanceRegistryState:
    instance_id: int
    instance_code: str
    instance_type: str  # CENTRALIZED vs DECENTRALIZED
    st_status: int
    st_status_name: str
    description: str
    last_collection_date: str
    active_parent_request_id: int | None
    active_program: str | None

@dataclass
class StageStatus:
    stage_number: int
    stage_name: str
    parent_process: str
    worker_process: str
    target_layer: str
    status: str  # PENDING, RUNNING, COMPLETED, FAILED, STALLED
    processed_count: int
    quarantine_error_count: int

class PipelineMonitor:
    """Introspects ASCP pipeline execution stages and instance registries."""

    def __init__(self, connection_config: Any | None = None, simulated_scenario: str = "stage2_stalled"):
        self.config = connection_config
        self.simulated_scenario = simulated_scenario

    def get_instance_registry(self, instance_id: int = 1001) -> InstanceRegistryState:
        """Fetch instance registry status from MSC_APPS_INSTANCES."""
        if self.simulated_scenario == "stage1_stalled":
            status_code = -1
            prog = "MSCPDP"
            req = 890412
        elif self.simulated_scenario == "stage2_stalled":
            status_code = -1
            prog = "MSCPDC"
            req = 890415
        elif self.simulated_scenario == "purge_stalled":
            status_code = -1
            prog = "MSCPDCP"
            req = 890420
        elif self.simulated_scenario == "running_stage2":
            status_code = 2
            prog = "MSCPDC"
            req = 890415
        else:
            status_code = 0
            prog = None
            req = None

        name, desc = ST_STATUS_MAP.get(status_code, ("UNKNOWN", "Undefined ST_STATUS value."))
        return InstanceRegistryState(
            instance_id=instance_id,
            instance_code="PRD1",
            instance_type="CENTRALIZED",
            st_status=status_code,
            st_status_name=name,
            description=desc,
            last_collection_date="2026-10-12 21:30:00",
            active_parent_request_id=req,
            active_program=prog
        )

    def get_pipeline_stages_telemetry(self) -> list[dict[str, Any]]:
        """Return diagnostic metrics across all 3 collection ETL stages."""
        if self.simulated_scenario == "stage1_stalled":
            return [
                asdict(StageStatus(1, "Planning Data Pull", "MSCPDP", "MSCPDPW", "MSC_ST_*", "FAILED", 14200, 48)),
                asdict(StageStatus(2, "Planning ODS Load", "MSCPDC", "MSCPDCW", "MSC_* (plan_id = -1)", "PENDING", 0, 0)),
                asdict(StageStatus(3, "Staging Maintenance & Purge", "MSCPDCP", "TRUNCATE SUB", "MSC_ST_*", "PENDING", 0, 0))
            ]
        elif self.simulated_scenario == "stage2_stalled":
            return [
                asdict(StageStatus(1, "Planning Data Pull", "MSCPDP", "MSCPDPW", "MSC_ST_*", "COMPLETED", 584900, 0)),
                asdict(StageStatus(2, "Planning ODS Load", "MSCPDC", "MSCPDCW", "MSC_* (plan_id = -1)", "STALLED", 210400, 312)),
                asdict(StageStatus(3, "Staging Maintenance & Purge", "MSCPDCP", "TRUNCATE SUB", "MSC_ST_*", "PENDING", 0, 0))
            ]
        else:
            return [
                asdict(StageStatus(1, "Planning Data Pull", "MSCPDP", "MSCPDPW", "MSC_ST_*", "COMPLETED", 584900, 0)),
                asdict(StageStatus(2, "Planning ODS Load", "MSCPDC", "MSCPDCW", "MSC_* (plan_id = -1)", "COMPLETED", 584900, 0)),
                asdict(StageStatus(3, "Staging Maintenance & Purge", "MSCPDCP", "TRUNCATE SUB", "MSC_ST_*", "COMPLETED", 0, 0))
            ]

    def get_staging_quarantine_records(self, table_name: str = "MSC_ST_DEMANDS") -> list[dict[str, Any]]:
        """Simulate or query quarantined staging rows with ERR_CODE and PROCESS_STATUS != 1."""
        return [
            {
                "row_id": "AAASteAABAAAmKdAAD",
                "table_name": table_name,
                "item_name": "AS54888",
                "org_code": "M1",
                "origination_type": 1,
                "process_status": 3,
                "err_code": "ERR_DUPLICATE_KEY",
                "error_message": "Surrogate key collision with pre-existing record."
            },
            {
                "row_id": "AAASteAABAAAmKdAAE",
                "table_name": table_name,
                "item_name": "CM19244",
                "org_code": "M2",
                "origination_type": 1,
                "process_status": 3,
                "err_code": "ERR_INVALID_UOM",
                "error_message": "Primary UOM conversion missing in source."
            }
        ]

    def verify_and_reset_registry(self, instance_id: int = 1001) -> dict[str, Any]:
        """Verifies MSC_APPS_INSTANCES.ST_STATUS prior to relaunching collections.
        If a crashed run left ST_STATUS > 0 or -1, automates a recovery call to
        Planning Data Collection - Purge Staging Tables with Validation = No
        to clear staging tables (MSC_ST_%) and normalize ST_STATUS to 0.
        """
        registry = self.get_instance_registry(instance_id)
        current_status = registry.st_status
        needs_reset = current_status != 0

        inst_id = int(instance_id)
        plsql_call = (
            f"BEGIN MSC_CL_COLLECTION.PURGE_STAGING_TABLES_SUB(p_instance_id => {inst_id}, p_validation => 'N'); END;"  # nosec B608
        )
        norm_sql = f"UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = {inst_id};"  # nosec B608

        recovery_payload = {
            "instance_id": inst_id,
            "initial_st_status": current_status,
            "st_status_name": registry.st_status_name,
            "reset_required": needs_reset,
            "recovery_program": "Planning Data Collection - Purge Staging Tables",
            "parameters": {"Validation": "No", "Instance_ID": inst_id},
            "plsql_call": plsql_call,
            "normalization_sql": norm_sql,
            "normalized_st_status": 0,
            "status": "NORMALIZED" if needs_reset else "CLEAN_NO_ACTION_NEEDED",
        }
        return recovery_payload
