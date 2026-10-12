"""Realistic Oracle ASCP Telemetry & Scenario Simulation Engine.
Provides ready-to-test scenarios for all 5 failure modes and healthy baseline.
"""

from typing import Dict, Any, List

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "ora_00054_mode6": {
        "name": "Scenario 1: TM Mode 6 Exclusive Lock Contention (ORA-00054)",
        "description": "Uncommitted manual session (SID 412) holding Mode 6 lock on MSC_ST_DEMANDS. ODS Load workers blocked.",
        "stage": "Stage 2: Planning ODS Load (MSCPDC)",
        "instance_id": 1001,
        "st_status": -1,
        "logs": [
            "[12-OCT-2025 04:12:01]: Launching Planning ODS Load Worker 1 (MSCPDCW)",
            "[12-OCT-2025 04:12:05]: Cause: ORA-00054: resource busy and acquire with NOWAIT specified on table MSC_ST_DEMANDS.",
            "[12-OCT-2025 04:12:06]: Action: Contact DBA to verify blocking locks on staging tables.",
            "[12-OCT-2025 04:12:10]: Worker process 31902 terminated with fatal error status."
        ],
        "lock_scenario": "ora_00054_mode6"
    },
    "ora_00001_unique": {
        "name": "Scenario 2: Surrogate Key Collision from Unpurged Staging (ORA-00001)",
        "description": "Previous Stage 3 purge failed. Residual staging rows collide during surrogate key generation.",
        "stage": "Stage 2: Planning ODS Load (MSCPDC)",
        "instance_id": 1001,
        "st_status": -1,
        "logs": [
            "[12-OCT-2025 05:01:22]: Beginning global surrogate key resolution for Instance PRD1 (1001).",
            "[12-OCT-2025 05:01:45]: ORA-00001: unique constraint (MSC.MSC_MAPPING_CLAUSES_U1) violated.",
            "[12-OCT-2025 05:01:46]: Collision on natural key (INVENTORY_ITEM_ID: 10492, ORG_ID: 204).",
            "[12-OCT-2025 05:01:50]: Error in package MSC_CL_COLLECTION.LOAD_DEMANDS."
        ],
        "lock_scenario": "no_locks"
    },
    "ora_14098_partition": {
        "name": "Scenario 3: Partition Exchange Index Mismatch (ORA-14098)",
        "description": "Structural or index definition mismatch during ALTER TABLE EXCHANGE PARTITION.",
        "stage": "Stage 2: Planning ODS Load (MSCPDC)",
        "instance_id": 1001,
        "st_status": -1,
        "logs": [
            "[12-OCT-2025 06:15:10]: Executing partition exchange: ALTER TABLE MSC_DEMANDS EXCHANGE PARTITION P_1001 WITH TABLE MSC_ST_DEMANDS INCLUDING INDEXES.",
            "[12-OCT-2025 06:15:12]: ORA-14098: index mismatch in ALTER TABLE EXCHANGE PARTITION.",
            "[12-OCT-2025 06:15:13]: Index MSC_DEMANDS_N1 column list differs from MSC_ST_DEMANDS_N1.",
            "[12-OCT-2025 06:15:15]: ODS Load worker aborted."
        ],
        "lock_scenario": "no_locks"
    },
    "ora_12571_link_drop": {
        "name": "Scenario 4: Source Snapshot DB Link Failure (ORA-12571)",
        "description": "Network timeout across database link during MSRFWOR snapshot refresh.",
        "stage": "Stage 1: Planning Data Pull (MSCPDP)",
        "instance_id": 1001,
        "st_status": -1,
        "logs": [
            "[12-OCT-2025 03:00:15]: Spawning MSRFWOR: Refresh Collection Snapshots on transactional source ERP.",
            "[12-OCT-2025 03:04:22]: ORA-12571: TNS:packet writer failure on db link TO_EBS_SOURCE.",
            "[12-OCT-2025 03:04:25]: DBMS_SNAPSHOT.REFRESH failed for MLOG$_OE_ORDER_LINES_ALL.",
            "[12-OCT-2025 03:04:30]: Planning Data Pull aborted during Phase 1 extraction."
        ],
        "lock_scenario": "no_locks"
    },
    "ora_02478_pipe_stall": {
        "name": "Scenario 5: Segment Max Extents & DBMS_PIPE Deadlock (ORA-02478)",
        "description": "Staging tablespace segment full; child pull worker crashed; parent waiting on DBMS_PIPE.",
        "stage": "Stage 1: Planning Data Pull (MSCPDP)",
        "instance_id": 1001,
        "st_status": -1,
        "logs": [
            "[12-OCT-2025 02:40:11]: MSCPDPW Worker 4 inserting into MSC_ST_SUPPLIES.",
            "[12-OCT-2025 02:42:01]: ORA-02478: maxextents reached for segment in tablespace APPS_TS_MEDIA.",
            "[12-OCT-2025 02:42:05]: Worker OS PID 41920 terminated abnormally without pipe signal.",
            "[12-OCT-2025 02:45:00]: Parent MSCPDP blocked in DBMS_PIPE.RECEIVE_MESSAGE('MSC_PIPE_1001')."
        ],
        "lock_scenario": "no_locks"
    },
    "healthy_pipeline": {
        "name": "Scenario 6: Baseline Healthy Collections Run",
        "description": "All 3 ETL stages successfully completed. Staging structures cleanly purged.",
        "stage": "Stage 3: Staging Maintenance & Purge (MSCPDCP)",
        "instance_id": 1001,
        "st_status": 0,
        "logs": [
            "[12-OCT-2025 01:00:00]: Planning Data Pull (MSCPDP) completed: 584,900 records staged.",
            "[12-OCT-2025 01:25:00]: Planning ODS Load (MSCPDC) completed: 584,900 records loaded to MSC_* (plan_id = -1).",
            "[12-OCT-2025 01:30:00]: Purge Staging Tables (MSCPDCP) completed successfully. ST_STATUS reset to 0."
        ],
        "lock_scenario": "no_locks"
    }
}

def parse_scenario_logs(scenario_key: str) -> List[Dict[str, Any]]:
    """Standardized scenario log parser routing directly through DrainLogParser."""
    from ascp_agent.drain_parser import DrainLogParser
    scenario = SCENARIOS.get(scenario_key)
    if not scenario:
        return []
    parser = DrainLogParser()
    return parser.parse_log_text("\n".join(scenario.get("logs", [])))
