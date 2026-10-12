"""ASCP Failure Modes & Diagnostic Remediation Matrix.
Codifies Oracle ASCP failure signatures, root causes, Metalink / MOS Doc IDs,
and technical remediation actions.
"""

from dataclasses import dataclass
from typing import Dict, Optional, List

@dataclass
class FailureModeDef:
    code: str
    error_pattern: str
    domain: str
    target_objects: List[str]
    root_cause_mechanism: str
    recommended_action: str
    risk_tier: str  # LOW, MEDIUM, HIGH
    remediation_procedure: str
    mos_doc_id: str
    detailed_explanation: str

FAILURE_CATALOG: Dict[str, FailureModeDef] = {
    "ORA-00054": FailureModeDef(
        code="ORA-00054",
        error_pattern="resource busy and acquire with NOWAIT specified",
        domain="Lock Contention",
        target_objects=["MSC_ST_DEMANDS", "MSC_ST_BOM", "MSC_ST_ROUTING", "MSC_ST_ITEM_CATEGORIES", "V$LOCKED_OBJECT"],
        root_cause_mechanism="TM Mode 6 Exclusive lock request blocked by uncommitted third-party DML, unindexed foreign key locks, or manual lock on target staging tables.",
        recommended_action="KILL_SESSION",
        risk_tier="HIGH",
        remediation_procedure="ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE;",
        mos_doc_id="Doc ID 223048.1 / 274853.1",
        detailed_explanation="During Stage 1 snapshot refreshes or Stage 3 staging truncations, exclusive table locks are required. Third-party locks block workers, causing parent MSCPDP / MSCPDC to stall indefinitely."
    ),
    "ORA-14098": FailureModeDef(
        code="ORA-14098",
        error_pattern="index mismatch in ALTER TABLE EXCHANGE PARTITION",
        domain="Partition Swap",
        target_objects=["MSC_DEMANDS", "MSC_SUPPLIES", "DBA_IND_COLUMNS", "DBA_INDEXES"],
        root_cause_mechanism="Structural, uniqueness, or column list mismatch between staging table indexes and target ODS base table partitioned indexes.",
        recommended_action="REBUILD_ALIGN_INDEXES",
        risk_tier="MEDIUM",
        remediation_procedure="EXEC MSC_CL_EXCHANGE_PARTTN.ALIGN_INDEX_DEFS('{table_name}');",
        mos_doc_id="Doc ID 249683.1 / 741498.1",
        detailed_explanation="MSCPDCW workers swap staging tables directly into partitioned base tables. If index structure, compression, or column nullability diverges, Oracle aborts the exchange."
    ),
    "ORA-02478": FailureModeDef(
        code="ORA-02478",
        error_pattern="maxextents reached for segment",
        domain="Infrastructure / IPC",
        target_objects=["MSC_ST_%", "V$DB_PIPES", "DBA_TABLESPACES"],
        root_cause_mechanism="Staging tablespace segment extent limit exhausted, or orphan worker process crash causing DBMS_PIPE buffer exhaustion and IPC stall.",
        recommended_action="RESET_PIPE_AND_EXTEND_STORAGE",
        risk_tier="MEDIUM",
        remediation_procedure="EXEC DBMS_PIPE.PURGE('MSC_PIPE_{inst}'); ALTER TABLESPACE APPS_TS_MEDIA ADD DATAFILE AUTOEXTEND ON;",
        mos_doc_id="Doc ID 308728.1",
        detailed_explanation="High-volume extraction runs can fill dedicated tablespaces. If pull workers abort silently, parent MSCPDP waits forever on empty DBMS_PIPE signals."
    ),
    "ORA-00001": FailureModeDef(
        code="ORA-00001",
        error_pattern="unique constraint.*violated",
        domain="Purge Maintenance",
        target_objects=["MSC_ST_%", "MSC_MAPPING_CLAUSES", "MSC_APPS_INSTANCES"],
        root_cause_mechanism="Stage 3 (MSCPDCP) failed or was skipped in previous run, leaving legacy interface rows. Stage 2 surrogate key resolution collides on duplicate natural keys.",
        recommended_action="PURGE_STAGING",
        risk_tier="MEDIUM",
        remediation_procedure="EXEC MSC_CL_PULL.PURGE_STAGING_TABLES_SUB({instance_id});",
        mos_doc_id="Doc ID 282498.1 / 158288.1",
        detailed_explanation="Pull workers append new rows alongside unpurged legacy records. Global surrogate key assignment generates duplicate key mappings, aborting Stage 2 ODS Load."
    ),
    "ORA-12571": FailureModeDef(
        code="ORA-12571",
        error_pattern="TNS:packet writer failure",
        domain="Source Snapshot",
        target_objects=["MLOG$_%", "DBA_DB_LINKS", "DBMS_SNAPSHOT"],
        root_cause_mechanism="Network packet transmission failure or TCP timeout across Oracle database link during MSRFWOR snapshot refresh on transactional source ERP.",
        recommended_action="RERUN_SNAPSHOT_FAST",
        risk_tier="LOW",
        remediation_procedure="EXEC DBMS_SNAPSHOT.REFRESH('{mview_name}', 'F');",
        mos_doc_id="Doc ID 203893.1 / 1060933.1",
        detailed_explanation="In centralized topologies, large snapshot delta writes over latent database links can encounter network drops, aborting MSRFWOR."
    )
}

def identify_failure_mode(log_text: str) -> Optional[FailureModeDef]:
    """Pattern match against log text to identify cataloged failure mode."""
    import re
    for code, defn in FAILURE_CATALOG.items():
        if code in log_text or re.search(defn.error_pattern, log_text, re.IGNORECASE):
            return defn
    return None
