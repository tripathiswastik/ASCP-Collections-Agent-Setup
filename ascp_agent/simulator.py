"""Realistic Oracle ASCP Telemetry & Scenario Simulation Engine.
Provides ready-to-test scenarios for all 5 failure modes and healthy baseline.
"""

from __future__ import annotations

from typing import Any

SCENARIOS: dict[str, dict[str, Any]] = {
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
    },
    "ora_00060_deadlock": {
        "name": "Scenario 7: Worker Cross-Table Deadlock (ORA-00060)",
        "description": "Mutual circular lock wait between concurrent MSCPDCW workers on MSC_ST_BOM and MSC_ST_ROUTINGS.",
        "stage": "Stage 2: Planning ODS Load (MSCPDC)",
        "instance_id": 1001,
        "st_status": -1,
        "logs": [
            "[12-OCT-2025 07:10:02]: MSCPDCW Worker 2 updating MSC_ST_BOM.",
            "[12-OCT-2025 07:10:04]: MSCPDCW Worker 3 updating MSC_ST_ROUTINGS.",
            "[12-OCT-2025 07:10:15]: ORA-00060: deadlock detected while waiting for resource.",
            "[12-OCT-2025 07:10:16]: See alert log trace file /u01/oracle/diag/trace/prd1_ora_4192.trc for deadlock graph.",
            "[12-OCT-2025 07:10:20]: Worker process 3192 terminated by kernel deadlock resolution."
        ],
        "lock_scenario": "no_locks"
    },
    "ora_01555_snapshot_old": {
        "name": "Scenario 8: Long-Running Extraction Snapshot Too Old (ORA-01555)",
        "description": "Source ERP undo tablespace retention exceeded during high-velocity snapshot log pull.",
        "stage": "Stage 1: Planning Data Pull (MSCPDP)",
        "instance_id": 1001,
        "st_status": -1,
        "logs": [
            "[12-OCT-2025 03:15:00]: MSRFWOR extracting transactional deltas from MLOG$_OE_ORDER_LINES_ALL.",
            "[12-OCT-2025 03:45:22]: ORA-01555: snapshot too old: rollback segment number 14 with name '_SYSSMU14_4129$' too small.",
            "[12-OCT-2025 03:45:25]: Query duration 1822 sec exceeded UNDO_RETENTION (900 sec).",
            "[12-OCT-2025 03:45:30]: Extraction worker aborted with read consistency error."
        ],
        "lock_scenario": "no_locks"
    },
    "ora_01653_tablespace_full": {
        "name": "Scenario 9: Staging Tablespace Extent Allocation Failure (ORA-01653)",
        "description": "Staging tablespace datafile quota exhausted during heavy batch extraction.",
        "stage": "Stage 1: Planning Data Pull (MSCPDP)",
        "instance_id": 1001,
        "st_status": -1,
        "logs": [
            "[12-OCT-2025 02:10:00]: MSCPDP inserting 2,400,000 supply records into MSC_ST_SUPPLIES.",
            "[12-OCT-2025 02:18:41]: ORA-01653: unable to extend table MSC.MSC_ST_SUPPLIES by 8192 in tablespace APPS_TS_STAGING.",
            "[12-OCT-2025 02:18:45]: Datafile /u02/oradata/prd1/apps_ts_staging01.dbf reached maxbytes without autoextend.",
            "[12-OCT-2025 02:18:50]: Bulk insert aborted due to insufficient disk quota."
        ],
        "lock_scenario": "no_locks"
    },
    "ora_04031_shared_pool": {
        "name": "Scenario 10: SGA Shared Pool Memory Fragmentation (ORA-04031)",
        "description": "SGA shared pool library cache unable to allocate contiguous chunk for package compilation.",
        "stage": "Stage 2: Planning ODS Load (MSCPDC)",
        "instance_id": 1001,
        "st_status": -1,
        "logs": [
            "[12-OCT-2025 05:22:10]: Compiling dynamic surrogate mapping package MSC_CL_COLLECTION.LOAD_SUPPLIES.",
            "[12-OCT-2025 05:22:14]: ORA-04031: unable to allocate 4128 bytes of shared memory ('shared pool','unknown object','sga heap(1,0)','kglsim heap').",
            "[12-OCT-2025 05:22:18]: High library cache fragmentation detected in SGA.",
            "[12-OCT-2025 05:22:20]: Worker aborted: PL/SQL package compilation failed."
        ],
        "lock_scenario": "no_locks"
    },
    "stuck_st_status_registry": {
        "name": "Scenario 11: Staging Status Registry Stuck Post-Crash (ST_STATUS)",
        "description": "Abnormal termination left MSC_APPS_INSTANCES.ST_STATUS set to 2 (LOAD_PROCESSING) with no active requests.",
        "stage": "Stage 1: Planning Data Pull (MSCPDP)",
        "instance_id": 1001,
        "st_status": 2,
        "logs": [
            "[12-OCT-2025 08:00:01]: Initiating Planning Data Pull parent request 890499.",
            "[12-OCT-2025 08:00:03]: ST_STATUS is not zero (current ST_STATUS = 2: LOAD_PROCESSING).",
            "[12-OCT-2025 08:00:04]: Cause: Another collections process is already running or prior run crashed without registry reset.",
            "[12-OCT-2025 08:00:10]: Concurrent request completed with error status."
        ],
        "lock_scenario": "no_locks"
    }
}

def parse_scenario_logs(scenario_key: str) -> list[dict[str, Any]]:
    """Standardized scenario log parser routing directly through DrainLogParser."""
    from ascp_agent.drain_parser import DrainLogParser
    scenario = SCENARIOS.get(scenario_key)
    if not scenario:
        return []
    parser = DrainLogParser()
    return parser.parse_log_text("\n".join(scenario.get("logs", [])))
