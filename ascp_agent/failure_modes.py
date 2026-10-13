"""ASCP Failure Modes & Diagnostic Remediation Matrix.
Codifies Oracle ASCP failure signatures, root causes, Metalink / MOS Doc IDs,
and technical remediation actions.
"""

from __future__ import annotations

from dataclasses import dataclass

from ascp_agent.lock_engine import get_sql_query


@dataclass
class FailureModeDef:
    code: str
    error_pattern: str
    domain: str
    target_objects: list[str]
    root_cause_mechanism: str
    recommended_action: str
    risk_tier: str  # LOW, MEDIUM, HIGH
    remediation_procedure: str
    mos_doc_id: str
    detailed_explanation: str
    diagnostic_query_id: str = "HIERARCHICAL_LOCK_TREE"

FAILURE_CATALOG: dict[str, FailureModeDef] = {
    "ORA-00054": FailureModeDef(
        code="ORA-00054",
        error_pattern="resource busy and acquire with NOWAIT specified",
        domain="Lock Contention",
        target_objects=["MSC_ST_DEMANDS", "MSC_ST_BOM", "MSC_ST_ROUTING", "MSC_ST_ITEM_CATEGORIES", "V$LOCKED_OBJECT"],
        root_cause_mechanism="TM Mode 6 Exclusive lock request blocked by uncommitted third-party DML, unindexed foreign key locks, or manual lock on target staging tables.",
        recommended_action="KILL_SESSION",
        risk_tier="HIGH",
        remediation_procedure=get_sql_query("KILL_SESSION"),
        mos_doc_id="Doc ID 223048.1 / 274853.1",
        detailed_explanation="During Stage 1 snapshot refreshes or Stage 3 staging truncations, exclusive table locks are required. Third-party locks block workers, causing parent MSCPDP / MSCPDC to stall indefinitely.",
        diagnostic_query_id="ORA_00054_LOCK_LOOKUP"
    ),
    "ORA-14098": FailureModeDef(
        code="ORA-14098",
        error_pattern="index mismatch in ALTER TABLE EXCHANGE PARTITION",
        domain="Partition Swap",
        target_objects=["MSC_DEMANDS", "MSC_SUPPLIES", "DBA_IND_COLUMNS", "DBA_INDEXES"],
        root_cause_mechanism="Structural, uniqueness, or column list mismatch between staging table indexes and target ODS base table partitioned indexes.",
        recommended_action="REBUILD_ALIGN_INDEXES",
        risk_tier="MEDIUM",
        remediation_procedure=get_sql_query("ALIGN_INDEXES"),
        mos_doc_id="Doc ID 249683.1 / 741498.1",
        detailed_explanation="MSCPDCW workers swap staging tables directly into partitioned base tables. If index structure, compression, or column nullability diverges, Oracle aborts the exchange.",
        diagnostic_query_id="ORA_14098_INDEX_CHECK"
    ),
    "ORA-02478": FailureModeDef(
        code="ORA-02478",
        error_pattern="maxextents reached for segment",
        domain="Infrastructure / IPC",
        target_objects=["MSC_ST_%", "V$DB_PIPES", "DBA_TABLESPACES"],
        root_cause_mechanism="Staging tablespace segment extent limit exhausted, or orphan worker process crash causing DBMS_PIPE buffer exhaustion and IPC stall.",
        recommended_action="RESET_PIPE_AND_EXTEND_STORAGE",
        risk_tier="MEDIUM",
        remediation_procedure=get_sql_query("PURGE_PIPE"),
        mos_doc_id="Doc ID 308728.1",
        detailed_explanation="High-volume extraction runs can fill dedicated tablespaces. If pull workers abort silently, parent MSCPDP waits forever on empty DBMS_PIPE signals.",
        diagnostic_query_id="DBMS_PIPE_STATUS_CHECK"
    ),
    "ORA-00001": FailureModeDef(
        code="ORA-00001",
        error_pattern="unique constraint.*violated",
        domain="Purge Maintenance",
        target_objects=["MSC_ST_%", "MSC_MAPPING_CLAUSES", "MSC_APPS_INSTANCES"],
        root_cause_mechanism="Stage 3 (MSCPDCP) failed or was skipped in previous run, leaving legacy interface rows. Stage 2 surrogate key resolution collides on duplicate natural keys.",
        recommended_action="PURGE_STAGING",
        risk_tier="MEDIUM",
        remediation_procedure=get_sql_query("PURGE_STAGING"),
        mos_doc_id="Doc ID 282498.1 / 158288.1",
        detailed_explanation="Pull workers append new rows alongside unpurged legacy records. Global surrogate key assignment generates duplicate key mappings, aborting Stage 2 ODS Load.",
        diagnostic_query_id="ST_STATUS_REGISTRY_CHECK"
    ),
    "ORA-12571": FailureModeDef(
        code="ORA-12571",
        error_pattern="TNS:packet writer failure",
        domain="Source Snapshot",
        target_objects=["MLOG$_%", "DBA_DB_LINKS", "DBMS_SNAPSHOT"],
        root_cause_mechanism="Network packet transmission failure or TCP timeout across Oracle database link during MSRFWOR snapshot refresh on transactional source ERP.",
        recommended_action="RERUN_SNAPSHOT_FAST",
        risk_tier="LOW",
        remediation_procedure=get_sql_query("REFRESH_SNAPSHOT"),
        mos_doc_id="Doc ID 203893.1 / 1060933.1",
        detailed_explanation="In centralized topologies, large snapshot delta writes over latent database links can encounter network drops, aborting MSRFWOR.",
        diagnostic_query_id="HIERARCHICAL_LOCK_TREE"
    ),
    "ORA-00060": FailureModeDef(
        code="ORA-00060",
        error_pattern="deadlock detected while waiting for resource",
        domain="Deadlock / Concurrency",
        target_objects=["MSC_ST_%", "V$SESSION", "ALERT.LOG"],
        root_cause_mechanism="Mutual circular wait deadlock between concurrent planning workers updating interrelated staging tables.",
        recommended_action="INSPECT_LOCKS",
        risk_tier="MEDIUM",
        remediation_procedure=get_sql_query("DEADLOCK_TRACE_CHECK"),
        mos_doc_id="Doc ID 60.1 / 1308892.1",
        detailed_explanation="Circular dependency between two workers. Kernel broke deadlock by terminating one statement with ORA-00060. Requires analyzing deadlock graph and requeuing worker.",
        diagnostic_query_id="DEADLOCK_TRACE_CHECK"
    ),
    "ORA-01555": FailureModeDef(
        code="ORA-01555",
        error_pattern="snapshot too old",
        domain="Undo / Snapshot Retention",
        target_objects=["V$UNDOSTAT", "MLOG$_%", "UNDO_RETENTION"],
        root_cause_mechanism="Query duration exceeded UNDO_RETENTION on source ERP instance during MSRFWOR snapshot extraction.",
        recommended_action="EXTEND_UNDO_RETENTION",
        risk_tier="LOW",
        remediation_procedure=get_sql_query("EXTEND_UNDO_RETENTION"),
        mos_doc_id="Doc ID 10630.1 / 1555.1",
        detailed_explanation="High uncommitted DML velocity overwritten required undo blocks for read consistency. Recommend increasing UNDO_RETENTION parameter.",
        diagnostic_query_id="UNDO_RETENTION_CHECK"
    ),
    "ORA-01653": FailureModeDef(
        code="ORA-01653",
        error_pattern="unable to extend table.*in tablespace",
        domain="Storage / Capacity",
        target_objects=["MSC_ST_%", "DBA_TABLESPACES", "DBA_DATA_FILES"],
        root_cause_mechanism="Staging tablespace datafile reached maximum size or ran out of free filesystem space during high-volume planning data pull.",
        recommended_action="EXTEND_TABLESPACE",
        risk_tier="MEDIUM",
        remediation_procedure=get_sql_query("EXTEND_TABLESPACE"),
        mos_doc_id="Doc ID 1653.1 / 281881.1",
        detailed_explanation="Dedicated tablespace hosting MSC_ST_* cannot allocate next extent. Autoextend was disabled or physical disk mount is full.",
        diagnostic_query_id="TABLESPACE_QUOTA_CHECK"
    ),
    "ORA-04031": FailureModeDef(
        code="ORA-04031",
        error_pattern="unable to allocate.*bytes of shared memory",
        domain="Memory / Shared Pool",
        target_objects=["V$SGASTAT", "V$SQLAREA", "SHARED_POOL_SIZE"],
        root_cause_mechanism="SGA shared pool memory fragmentation preventing contiguous allocation during PL/SQL compilation of MSC collection packages.",
        recommended_action="FLUSH_SHARED_POOL",
        risk_tier="MEDIUM",
        remediation_procedure=get_sql_query("FLUSH_SHARED_POOL"),
        mos_doc_id="Doc ID 146528.1 / 4031.1",
        detailed_explanation="Severe heap fragmentation in shared pool library cache. Requires flushing shared pool or pinning large packages with DBMS_SHARED_POOL.KEEP.",
        diagnostic_query_id="SHARED_POOL_FREE_CHECK"
    ),
    "STUCK_ST_STATUS": FailureModeDef(
        code="STUCK_ST_STATUS",
        error_pattern="ST_STATUS is not zero|ST_STATUS = [123]|collection already running|staging status remains",
        domain="Orchestration / Registry",
        target_objects=["MSC_APPS_INSTANCES", "FND_CONCURRENT_REQUESTS"],
        root_cause_mechanism="Aborted collection left MSC_APPS_INSTANCES.ST_STATUS flagged as active (1, 2, or 3) with zero running worker requests.",
        recommended_action="RESET_REGISTRY",
        risk_tier="HIGH",
        remediation_procedure=get_sql_query("RESET_REGISTRY"),
        mos_doc_id="Doc ID 206497.1 / 274853.1",
        detailed_explanation="Staging registry flag ST_STATUS is locked in a non-zero processing state following an unhandled crash, blocking subsequent collection attempts.",
        diagnostic_query_id="ST_STATUS_REGISTRY_CHECK"
    )
}

def identify_failure_mode(log_text: str) -> FailureModeDef | None:
    """Pattern match against log text to identify cataloged failure mode."""
    import re
    for code, defn in FAILURE_CATALOG.items():
        if code in log_text or re.search(defn.error_pattern, log_text, re.IGNORECASE):
            return defn
    return None
