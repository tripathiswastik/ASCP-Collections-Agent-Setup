"""Oracle ASCP Domain Knowledge Base & Diagnostic Rulebook Catalog.
Provides structured diagnostic patterns, evidence queries, confirmed-cause criteria,
competing hypotheses, safe next checks, and guarded remediation specifications across
all 6 ASCP failure domains:
1. Collections & Source-System Data Freshness (PULL / MSRFWOR / DB Link)
2. Planning ODS ETL & Interface Layer (LOAD / MSCPDP / MSCPDC)
3. Planning Exceptions & Supply-Demand Mismatches (PDS / Exceptions)
4. Resource Capacity Constraints & Bottlenecks (MSRCS / Routing)
5. Sourcing Rules, Lead Times, Calendars & Master Data (Sourcing / Master Data)
6. Memory, Runtime, & Database Contention (Locks / SGA / Undo / Tablespace)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FailureDomain(str, Enum):
    COLLECTIONS_DATA_FRESHNESS = "COLLECTIONS_DATA_FRESHNESS"
    PLANNING_ODS_ETL = "PLANNING_ODS_ETL"
    PLANNING_EXCEPTIONS_DEMAND_SUPPLY = "PLANNING_EXCEPTIONS_DEMAND_SUPPLY"
    RESOURCE_CAPACITY_BOTTLENECK = "RESOURCE_CAPACITY_BOTTLENECK"
    SOURCING_RULES_MASTER_DATA = "SOURCING_RULES_MASTER_DATA"
    MEMORY_DATABASE_CONTENTION = "MEMORY_DATABASE_CONTENTION"
    HEALTHY_BASELINE = "HEALTHY_BASELINE"


class IncidentSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskTier(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class EvidenceSignature:
    """Pattern or telemetry check needed to support or refute a diagnosis."""
    code: str
    description: str
    evidence_type: str  # LOG_PATTERN, SQL_QUERY, METRIC_CHECK, REGISTRY_STATE
    query_template: str | None = None
    required_match: str | None = None
    is_mandatory: bool = True
    weight: float = 1.0


@dataclass
class RemediationSpec:
    """Guarded remediation specification tied to a verified root cause."""
    action_name: str
    risk_tier: RiskTier
    requires_approval: bool
    requires_dry_run: bool
    description: str
    recommended_sql: str | None = None
    preconditions: list[str] = field(default_factory=list)
    rollback_plan: str = "Rollback transaction or restore prior parameter setting."
    verification_check: str = "SELECT 1 FROM DUAL"


@dataclass
class DiagnosticRule:
    """Structured rulebook for an ASCP failure class."""
    rule_id: str
    domain: FailureDomain
    primary_code: str
    title: str
    subsystem: str
    severity: IncidentSeverity
    summary: str
    evidence_signatures: list[EvidenceSignature]
    competing_hypotheses: list[str]
    missing_evidence_indicators: list[str]
    safe_next_checks: list[str]
    remediation_spec: RemediationSpec | None = None


# ---------------------------------------------------------------------------
# Structured ASCP Diagnostic Rulebook Catalog
# ---------------------------------------------------------------------------

ASCP_KNOWLEDGE_RULES: dict[str, DiagnosticRule] = {
    # 1. Mode 6 Exclusive Lock Contention
    "RULE_ORA_00054_MODE6": DiagnosticRule(
        rule_id="RULE_ORA_00054_MODE6",
        domain=FailureDomain.MEMORY_DATABASE_CONTENTION,
        primary_code="ORA-00054",
        title="Mode 6 Exclusive Lock Contention on Staging Interface Table",
        subsystem="Stage 2: Planning ODS Load (MSCPDC)",
        severity=IncidentSeverity.CRITICAL,
        summary="Uncommitted manual user session holding TM Mode 6 Exclusive lock on staging table, blocking parallel ODS Load workers.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-ORA54",
                description="ORA-00054 resource busy log line in concurrent worker log",
                evidence_type="LOG_PATTERN",
                required_match="ORA-00054",
                is_mandatory=True,
                weight=0.35,
            ),
            EvidenceSignature(
                code="EV-LOCK-ROOT-BLOCKER",
                description="v$locked_object / v$session hierarchical lock tree detects root blocker holding Mode 6 lock",
                evidence_type="SQL_QUERY",
                query_template="SELECT sid, serial#, locked_mode FROM v$locked_object lo JOIN v$session s ON lo.session_id = s.sid WHERE locked_mode = 6",
                required_match="MODE_6_EXCLUSIVE",
                is_mandatory=True,
                weight=0.45,
            ),
            EvidenceSignature(
                code="EV-REG-STALLED",
                description="MSC_APPS_INSTANCES.ST_STATUS set to -1 indicating stalled ETL",
                evidence_type="REGISTRY_STATE",
                required_match="ST_STATUS = -1",
                is_mandatory=False,
                weight=0.20,
            ),
        ],
        competing_hypotheses=[
            "Direct path bulk loader contention during parallel exchange",
            "Third-party DBA backup script locking table partition",
            "Transient transaction waiting on lock with short NOWAIT timeout",
        ],
        missing_evidence_indicators=[
            "v$session.sql_id and active v$sql statement of holding session",
            "Holding session OS process status and idle duration",
        ],
        safe_next_checks=[
            "Run hierarchical lock tree query to verify root blocker is not PMON/SMON",
            "Inspect holding session v$sql to verify if session is idle or executing DDL",
            "Query v$transaction to calculate uncommitted rollback record volume (used_urec)",
        ],
        remediation_spec=RemediationSpec(
            action_name="KILL_SESSION",
            risk_tier=RiskTier.HIGH,
            requires_approval=True,
            requires_dry_run=True,
            description="Terminate blocking non-system Oracle session via ALTER SYSTEM KILL SESSION IMMEDIATE.",
            recommended_sql="ALTER SYSTEM KILL SESSION '{target_sid},{target_serial}' IMMEDIATE",
            preconditions=[
                "Target SID must exist and hold Mode 6 lock on affected table",
                "Target session must NOT be Oracle background process or internal worker",
                "Session undo record count (used_urec) must be below 50,000 to prevent PMON rollback freeze",
            ],
            rollback_plan="No rollback for killed session; client must reconnect.",
            verification_check="SELECT COUNT(*) FROM v$locked_object WHERE object_id = :obj_id",
        ),
    ),

    # 2. Surrogate Key Collision from Unpurged Staging
    "RULE_ORA_00001_SURROGATE": DiagnosticRule(
        rule_id="RULE_ORA_00001_SURROGATE",
        domain=FailureDomain.PLANNING_ODS_ETL,
        primary_code="ORA-00001",
        title="Surrogate Key Collision from Residual Unpurged Staging Rows",
        subsystem="Stage 2: Planning ODS Load (MSCPDC)",
        severity=IncidentSeverity.CRITICAL,
        summary="Unique constraint violation in MSC surrogate mapping table due to uncleared staging data from a prior crashed run.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-ORA01",
                description="ORA-00001 unique constraint violation in ODS load worker log",
                evidence_type="LOG_PATTERN",
                required_match="ORA-00001",
                is_mandatory=True,
                weight=0.40,
            ),
            EvidenceSignature(
                code="EV-LOG-SURROGATE",
                description="Collision on surrogate key generation in MSC_CL_COLLECTION package",
                evidence_type="LOG_PATTERN",
                required_match="surrogate key",
                is_mandatory=True,
                weight=0.30,
            ),
            EvidenceSignature(
                code="EV-STAGING-DUPLICATES",
                description="Residual staging rows present from previous aborted collection",
                evidence_type="SQL_QUERY",
                query_template="SELECT count(*) FROM msc_st_demands WHERE process_status = 3",
                is_mandatory=False,
                weight=0.30,
            ),
        ],
        competing_hypotheses=[
            "Data corruption in source ERP inventory item natural keys",
            "Simultaneous collections jobs launched concurrently for the same instance",
            "Sequence cache wrap-around on MSC surrogate key sequence",
        ],
        missing_evidence_indicators=[
            "Exact natural key collision attributes (INVENTORY_ITEM_ID, ORG_ID)",
            "Timestamp of prior collection run to verify abnormal termination",
        ],
        safe_next_checks=[
            "Query MSC_ST_DEMANDS for duplicate natural keys with conflicting surrogate mappings",
            "Verify MSC_APPS_INSTANCES.LAST_COLLECTION_DATE and completion status",
        ],
        remediation_spec=RemediationSpec(
            action_name="PURGE_STAGING",
            risk_tier=RiskTier.MEDIUM,
            requires_approval=False,
            requires_dry_run=True,
            description="Execute Planning Data Collection - Purge Staging Tables with Validation = No to clean staging artifacts and reset registry.",
            recommended_sql="BEGIN MSC_CL_COLLECTION.PURGE_STAGING_TABLES_SUB(p_instance_id => {instance_id}, p_validation => 'N'); END;",
            preconditions=[
                "No active MSCPDC or MSCPDP processes currently executing for this instance",
                "Instance ID must match a registered instance in MSC_APPS_INSTANCES",
            ],
            rollback_plan="Relaunch full collections pull after staging truncation.",
            verification_check="SELECT COUNT(*) FROM msc_st_demands",
        ),
    ),

    # 3. Partition Exchange Index Mismatch
    "RULE_ORA_14098_INDEX_MISMATCH": DiagnosticRule(
        rule_id="RULE_ORA_14098_INDEX_MISMATCH",
        domain=FailureDomain.PLANNING_ODS_ETL,
        primary_code="ORA-14098",
        title="Partition Exchange Index Definition Mismatch (INCLUDING INDEXES)",
        subsystem="Stage 2: Planning ODS Load (MSCPDC)",
        severity=IncidentSeverity.HIGH,
        summary="ALTER TABLE EXCHANGE PARTITION aborted because index definitions or column order differ between staging table and target partitioned ODS table.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-ORA14098",
                description="ORA-14098 index mismatch in ALTER TABLE EXCHANGE PARTITION",
                evidence_type="LOG_PATTERN",
                required_match="ORA-14098",
                is_mandatory=True,
                weight=0.45,
            ),
            EvidenceSignature(
                code="EV-LOG-EXCHANGE",
                description="Partition exchange statement logged in concurrent worker log",
                evidence_type="LOG_PATTERN",
                required_match="EXCHANGE PARTITION",
                is_mandatory=True,
                weight=0.30,
            ),
            EvidenceSignature(
                code="EV-DDL-INDEX-DIFF",
                description="Schema difference between MSC_* and MSC_ST_* index columns or uniqueness",
                evidence_type="SQL_QUERY",
                query_template="SELECT index_name, column_name, column_position FROM all_ind_columns WHERE table_name IN ('MSC_DEMANDS', 'MSC_ST_DEMANDS')",
                is_mandatory=False,
                weight=0.25,
            ),
        ],
        competing_hypotheses=[
            "Custom DBA index added to ODS table without corresponding staging table index",
            "One or more partition local indexes in UNUSABLE state prior to exchange",
            "Table compression or PCTFREE clause mismatch between partition and staging table",
        ],
        missing_evidence_indicators=[
            "Specific index name and column position difference report",
            "Index uniqueness and compression settings comparison",
        ],
        safe_next_checks=[
            "Query dba_ind_columns to compare exact column lists of staging vs target table indexes",
            "Check dba_ind_partitions for indexes in UNUSABLE state",
        ],
        remediation_spec=RemediationSpec(
            action_name="ALIGN_INDEXES",
            risk_tier=RiskTier.MEDIUM,
            requires_approval=True,
            requires_dry_run=True,
            description="Execute MSC_CL_EXCHANGE_PARTTN.ALIGN_INDEX_DEFS to align index structures on staging tables.",
            recommended_sql="BEGIN MSC_CL_EXCHANGE_PARTTN.ALIGN_INDEX_DEFS('{target_table}'); END;",
            preconditions=[
                "Target table must belong to MSC schema and be registered for partition exchange",
                "No DDL locks currently held on target table or partition",
            ],
            rollback_plan="Rebuild altered index back to prior DDL definition.",
            verification_check="SELECT status FROM all_indexes WHERE table_name = :tbl_name AND status != 'VALID'",
        ),
    ),

    # 4. Source Snapshot DB Link Network Failure
    "RULE_ORA_12571_DB_LINK": DiagnosticRule(
        rule_id="RULE_ORA_12571_DB_LINK",
        domain=FailureDomain.COLLECTIONS_DATA_FRESHNESS,
        primary_code="ORA-12571",
        title="Source Snapshot Refresh DB Link Packet Writer Failure",
        subsystem="Stage 1: Planning Data Pull (MSCPDP)",
        severity=IncidentSeverity.HIGH,
        summary="TNS packet writer failure across database link to source ERP during MSRFWOR snapshot refresh.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-ORA12571",
                description="ORA-12571 TNS:packet writer failure in MSRFWOR log",
                evidence_type="LOG_PATTERN",
                required_match="ORA-12571",
                is_mandatory=True,
                weight=0.45,
            ),
            EvidenceSignature(
                code="EV-LOG-DBLINK",
                description="Database link reference to transactional source ERP",
                evidence_type="LOG_PATTERN",
                required_match="db link",
                is_mandatory=True,
                weight=0.30,
            ),
            EvidenceSignature(
                code="EV-LOG-MSRFWOR",
                description="DBMS_SNAPSHOT.REFRESH failed on transactional source snapshot log",
                evidence_type="LOG_PATTERN",
                required_match="DBMS_SNAPSHOT.REFRESH",
                is_mandatory=False,
                weight=0.25,
            ),
        ],
        competing_hypotheses=[
            "Firewall state-table timeout severing idle long-running TCP connection",
            "Transactional source Oracle instance rebooted or experienced PMON crash",
            "MTU packet fragmentation mismatch across network switch",
        ],
        missing_evidence_indicators=[
            "Source ERP listener log status and alert log at failure timestamp",
            "DB link connectivity check (tnsping & SELECT 1 FROM DUAL@link)",
        ],
        safe_next_checks=[
            "Test database link connectivity: SELECT SYSDATE FROM DUAL@TO_EBS_SOURCE",
            "Check source ERP snapshot log row counts (SELECT count(*) FROM MLOG$_OE_ORDER_LINES)",
        ],
        remediation_spec=RemediationSpec(
            action_name="REFRESH_SNAPSHOT",
            risk_tier=RiskTier.LOW,
            requires_approval=False,
            requires_dry_run=False,
            description="Re-invoke DBMS_SNAPSHOT.REFRESH in fast incremental mode after verifying DB link connectivity.",
            recommended_sql="BEGIN DBMS_SNAPSHOT.REFRESH('{mview_name}', 'F'); END;",
            preconditions=[
                "DB link to source ERP is reachable (SELECT 1 FROM DUAL@link returns 1)",
                "No stale lock on source ERP MLOG$ table",
            ],
            rollback_plan="None; failed refresh can be repeated or switched to Complete refresh.",
            verification_check="SELECT last_refresh_date FROM all_mviews WHERE mview_name = :mv",
        ),
    ),

    # 5. Segment Max Extents & DBMS_PIPE Deadlock
    "RULE_ORA_02478_PIPE_STALL": DiagnosticRule(
        rule_id="RULE_ORA_02478_PIPE_STALL",
        domain=FailureDomain.COLLECTIONS_DATA_FRESHNESS,
        primary_code="ORA-02478",
        title="Tablespace Max Extents Reached with DBMS_PIPE Parent Wait Stall",
        subsystem="Stage 1: Planning Data Pull (MSCPDP)",
        severity=IncidentSeverity.CRITICAL,
        summary="Child pull worker hit maxextents, crashed abnormally without signalling parent, leaving parent blocked indefinitely in DBMS_PIPE.RECEIVE_MESSAGE.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-ORA02478",
                description="ORA-02478 maxextents reached in child worker log",
                evidence_type="LOG_PATTERN",
                required_match="ORA-02478",
                is_mandatory=True,
                weight=0.40,
            ),
            EvidenceSignature(
                code="EV-LOG-PIPE-WAIT",
                description="Parent process blocked waiting on DBMS_PIPE signal",
                evidence_type="LOG_PATTERN",
                required_match="DBMS_PIPE",
                is_mandatory=True,
                weight=0.35,
            ),
            EvidenceSignature(
                code="EV-SESSION-WAIT-PIPE",
                description="Parent session wait event shows 'pipe get' or 'pipe put'",
                evidence_type="SQL_QUERY",
                query_template="SELECT sid, event, seconds_in_wait FROM v$session WHERE event LIKE 'pipe%'",
                is_mandatory=False,
                weight=0.25,
            ),
        ],
        competing_hypotheses=[
            "Child pull worker killed by OS Out-Of-Memory (OOM) killer without pipe signal",
            "DBMS_PIPE buffer exhaustion due to message size exceeding MAX_PIPE_SIZE",
        ],
        missing_evidence_indicators=[
            "Storage quota and maxextents setting on affected tablespace",
            "Operating system syslog/dmesg for child worker termination signal",
        ],
        safe_next_checks=[
            "Query DBA_TABLESPACES and DBA_SEGMENTS for extent allocation count",
            "Inspect v$db_pipes for stale pipe message buffers",
        ],
        remediation_spec=RemediationSpec(
            action_name="PURGE_PIPE",
            risk_tier=RiskTier.MEDIUM,
            requires_approval=True,
            requires_dry_run=False,
            description="Purge stale DBMS_PIPE buffers and unblock waiting parent process.",
            recommended_sql="BEGIN DBMS_PIPE.PURGE('MSC_PIPE_{instance_code}'); END;",
            preconditions=[
                "Child worker process has definitely terminated",
                "Pipe belongs to ASCP collection infrastructure",
            ],
            rollback_plan="Recreate pipe if required: DBMS_PIPE.CREATE_PIPE.",
            verification_check="SELECT COUNT(*) FROM v$db_pipes WHERE name = :pipe_name",
        ),
    ),

    # 6. Snapshot Too Old (ORA-01555)
    "RULE_ORA_01555_UNDO_RETENTION": DiagnosticRule(
        rule_id="RULE_ORA_01555_UNDO_RETENTION",
        domain=FailureDomain.MEMORY_DATABASE_CONTENTION,
        primary_code="ORA-01555",
        title="Snapshot Too Old: Query Duration Exceeded UNDO_RETENTION",
        subsystem="Stage 1: Planning Data Pull (MSCPDP)",
        severity=IncidentSeverity.HIGH,
        summary="Source ERP transactional deltas query exceeded UNDO_RETENTION during heavy concurrent DML, causing rollback segment overwrite and read consistency error.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-ORA1555",
                description="ORA-01555 snapshot too old in worker log",
                evidence_type="LOG_PATTERN",
                required_match="ORA-01555",
                is_mandatory=True,
                weight=0.50,
            ),
            EvidenceSignature(
                code="EV-LOG-UNDO-EXCEEDED",
                description="Query duration exceeded UNDO_RETENTION parameter",
                evidence_type="LOG_PATTERN",
                required_match="UNDO_RETENTION",
                is_mandatory=True,
                weight=0.30,
            ),
            EvidenceSignature(
                code="EV-PARAM-UNDO",
                description="v$parameter UNDO_RETENTION is set lower than query execution duration",
                evidence_type="SQL_QUERY",
                query_template="SELECT value FROM v$parameter WHERE name = 'undo_retention'",
                is_mandatory=False,
                weight=0.20,
            ),
        ],
        competing_hypotheses=[
            "High rate of uncommitted UPDATE/DELETE on source ERP table forcing fast undo segment reuse",
            "Slow storage I/O on source ERP causing extraction query to take 3x normal duration",
            "Source ERP undo tablespace size capped without AUTOEXTEND",
        ],
        missing_evidence_indicators=[
            "v$undostat history of UNXPSTEALCNT and EXPSTEALCNT on source instance",
            "Extraction query execution plan on MLOG$_OE_ORDER_LINES_ALL",
        ],
        safe_next_checks=[
            "Query v$parameter for current UNDO_RETENTION and v$undostat for steal counts",
            "Check source table row count and snapshot log volume",
        ],
        remediation_spec=RemediationSpec(
            action_name="EXTEND_UNDO_RETENTION",
            risk_tier=RiskTier.LOW,
            requires_approval=False,
            requires_dry_run=False,
            description="Dynamically increase UNDO_RETENTION parameter to eliminate read consistency failures.",
            recommended_sql="ALTER SYSTEM SET UNDO_RETENTION = 10800 SCOPE=BOTH",
            preconditions=[
                "Undo tablespace has sufficient free disk space to retain 3 hours of undo data",
            ],
            rollback_plan="ALTER SYSTEM SET UNDO_RETENTION = 900 SCOPE=BOTH",
            verification_check="SELECT value FROM v$parameter WHERE name = 'undo_retention'",
        ),
    ),

    # 7. Worker Cross-Table Deadlock (ORA-00060)
    "RULE_ORA_00060_DEADLOCK": DiagnosticRule(
        rule_id="RULE_ORA_00060_DEADLOCK",
        domain=FailureDomain.MEMORY_DATABASE_CONTENTION,
        primary_code="ORA-00060",
        title="Worker Cross-Table Circular Deadlock Detected",
        subsystem="Stage 2: Planning ODS Load (MSCPDC)",
        severity=IncidentSeverity.CRITICAL,
        summary="Circular lock wait between concurrent MSCPDCW workers updating BOM and ROUTINGS tables.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-ORA60",
                description="ORA-00060 deadlock detected in worker log",
                evidence_type="LOG_PATTERN",
                required_match="ORA-00060",
                is_mandatory=True,
                weight=0.50,
            ),
            EvidenceSignature(
                code="EV-LOG-DEADLOCK-GRAPH",
                description="Deadlock graph referenced in alert trace file",
                evidence_type="LOG_PATTERN",
                required_match="deadlock graph",
                is_mandatory=True,
                weight=0.30,
            ),
            EvidenceSignature(
                code="EV-TRACE-DEADLOCK",
                description="Alert log contains Deadlock Graph indicating cyclic wait",
                evidence_type="SQL_QUERY",
                query_template="SELECT * FROM v$diag_alert_ext WHERE message_text LIKE '%ORA-00060%'",
                is_mandatory=False,
                weight=0.20,
            ),
        ],
        competing_hypotheses=[
            "Unindexed foreign key constraint on child table causing table-level lock escalation",
            "Parallel workers updating shared surrogate key mapping partition in inverse order",
        ],
        missing_evidence_indicators=[
            "Deadlock graph trace file contents from /u01/oracle/diag/trace",
            "SQL IDs of both colliding worker threads",
        ],
        safe_next_checks=[
            "Inspect alert log trace file for SQL statements participating in deadlock cycle",
            "Verify foreign key index coverage on MSC_ST_BOM and MSC_ST_ROUTINGS",
        ],
        remediation_spec=RemediationSpec(
            action_name="KILL_SESSION",
            risk_tier=RiskTier.HIGH,
            requires_approval=True,
            requires_dry_run=True,
            description="Terminate survivor blocking worker session holding remaining lock so concurrent manager can retry clean.",
            recommended_sql="ALTER SYSTEM KILL SESSION '{target_sid},{target_serial}' IMMEDIATE",
            preconditions=[
                "Survivor session identified in lock tree",
                "Deadlock graph confirmed circular wait",
            ],
            rollback_plan="Relaunch worker via concurrent manager.",
            verification_check="SELECT COUNT(*) FROM v$session WHERE sid = :target_sid",
        ),
    ),

    # 8. Staging Tablespace Extent Allocation Failure (ORA-01653)
    "RULE_ORA_01653_STORAGE": DiagnosticRule(
        rule_id="RULE_ORA_01653_STORAGE",
        domain=FailureDomain.MEMORY_DATABASE_CONTENTION,
        primary_code="ORA-01653",
        title="Staging Tablespace Datafile Quota Exhaustion",
        subsystem="Stage 1: Planning Data Pull (MSCPDP)",
        severity=IncidentSeverity.HIGH,
        summary="Bulk insert into staging table aborted because tablespace reached maxbytes without autoextend enabled.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-ORA1653",
                description="ORA-01653 unable to extend table in worker log",
                evidence_type="LOG_PATTERN",
                required_match="ORA-01653",
                is_mandatory=True,
                weight=0.45,
            ),
            EvidenceSignature(
                code="EV-LOG-MAXBYTES",
                description="Datafile reached maxbytes without autoextend",
                evidence_type="LOG_PATTERN",
                required_match="maxbytes",
                is_mandatory=True,
                weight=0.30,
            ),
            EvidenceSignature(
                code="EV-DBA-FREE-SPACE",
                description="DBA_FREE_SPACE reports 0 contiguous extents available",
                evidence_type="SQL_QUERY",
                query_template="SELECT tablespace_name, sum(bytes)/1024/1024 free_mb FROM dba_free_space GROUP BY tablespace_name",
                is_mandatory=False,
                weight=0.25,
            ),
        ],
        competing_hypotheses=[
            "Storage array filesystem (LUN/volume) full preventing OS datafile extension",
            "User quota on tablespace exhausted despite tablespace free space existing",
        ],
        missing_evidence_indicators=[
            "Operating system disk volume available bytes (df -h /u02/oradata)",
            "User tablespace quota allocation in DBA_TS_QUOTAS",
        ],
        safe_next_checks=[
            "Check dba_data_files for AUTOEXTEND and MAXBYTES on APPS_TS_STAGING",
            "Verify underlying OS mount space",
        ],
        remediation_spec=RemediationSpec(
            action_name="EXTEND_TABLESPACE",
            risk_tier=RiskTier.MEDIUM,
            requires_approval=True,
            requires_dry_run=False,
            description="Add autoextensible datafile storage to staging tablespace.",
            recommended_sql="ALTER TABLESPACE APPS_TS_STAGING ADD DATAFILE SIZE 100M AUTOEXTEND ON NEXT 50M",
            preconditions=[
                "Operating system volume has at least 10GB free space",
                "Tablespace name matches valid Oracle identifier in DBA_TABLESPACES",
            ],
            rollback_plan="ALTER TABLESPACE APPS_TS_STAGING DROP DATAFILE :file_name",
            verification_check="SELECT bytes FROM dba_data_files WHERE tablespace_name = 'APPS_TS_STAGING'",
        ),
    ),

    # 9. SGA Shared Pool Memory Fragmentation (ORA-04031)
    "RULE_ORA_04031_SHARED_POOL": DiagnosticRule(
        rule_id="RULE_ORA_04031_SHARED_POOL",
        domain=FailureDomain.MEMORY_DATABASE_CONTENTION,
        primary_code="ORA-04031",
        title="SGA Shared Pool Library Cache Memory Fragmentation",
        subsystem="Stage 2: Planning ODS Load (MSCPDC)",
        severity=IncidentSeverity.HIGH,
        summary="SGA shared pool library cache unable to allocate contiguous chunk for dynamic PL/SQL package compilation.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-ORA4031",
                description="ORA-04031 unable to allocate shared memory in worker log",
                evidence_type="LOG_PATTERN",
                required_match="ORA-04031",
                is_mandatory=True,
                weight=0.45,
            ),
            EvidenceSignature(
                code="EV-LOG-FRAGMENTATION",
                description="Library cache or shared pool heap fragmentation detected",
                evidence_type="LOG_PATTERN",
                required_match="shared pool",
                is_mandatory=True,
                weight=0.30,
            ),
            EvidenceSignature(
                code="EV-SGA-STAT",
                description="v$sgastat reports free memory chunk fragmentation",
                evidence_type="SQL_QUERY",
                query_template="SELECT name, bytes FROM v$sgastat WHERE pool = 'shared pool' AND name = 'free memory'",
                is_mandatory=False,
                weight=0.25,
            ),
        ],
        competing_hypotheses=[
            "Literal SQL query flood without bind variables blowing library cache",
            "SGA_TARGET / SHARED_POOL_SIZE under-sized for concurrent collection load",
        ],
        missing_evidence_indicators=[
            "v$sqlarea count of unshared single-execution SQL statements",
            "v$shared_pool_reserved chunk allocation requests",
        ],
        safe_next_checks=[
            "Query v$sgastat for free memory size in shared pool",
            "Check v$sql for high version counts on MSC packages",
        ],
        remediation_spec=RemediationSpec(
            action_name="FLUSH_SHARED_POOL",
            risk_tier=RiskTier.MEDIUM,
            requires_approval=True,
            requires_dry_run=False,
            description="Flush SGA shared pool library cache to coalesce free memory chunks.",
            recommended_sql="ALTER SYSTEM FLUSH SHARED_POOL",
            preconditions=[
                "Executed during non-peak batch window to minimize hard-parse CPU spikes",
            ],
            rollback_plan="None; library cache repopulates dynamically.",
            verification_check="SELECT bytes FROM v$sgastat WHERE name = 'free memory'",
        ),
    ),

    # 10. Stuck Registry Flag Post-Crash (ST_STATUS = 2)
    "RULE_STUCK_ST_STATUS_REGISTRY": DiagnosticRule(
        rule_id="RULE_STUCK_ST_STATUS_REGISTRY",
        domain=FailureDomain.PLANNING_ODS_ETL,
        primary_code="STUCK_ST_STATUS",
        title="Staging Status Registry Stuck Post-Crash (ST_STATUS = 2)",
        subsystem="Stage 1: Planning Data Pull (MSCPDP)",
        severity=IncidentSeverity.HIGH,
        summary="Prior collections process terminated abnormally, leaving MSC_APPS_INSTANCES.ST_STATUS set to 2 (LOAD_PROCESSING) with no active requests.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-ST-STATUS",
                description="ST_STATUS is not zero in concurrent request log",
                evidence_type="LOG_PATTERN",
                required_match="ST_STATUS is not zero",
                is_mandatory=True,
                weight=0.45,
            ),
            EvidenceSignature(
                code="EV-REGISTRY-VALUE",
                description="MSC_APPS_INSTANCES reports ST_STATUS = 2 but FND_CONCURRENT_REQUESTS has no running processes",
                evidence_type="REGISTRY_STATE",
                required_match="ST_STATUS = 2",
                is_mandatory=True,
                weight=0.35,
            ),
            EvidenceSignature(
                code="EV-NO-ACTIVE-REQUESTS",
                description="No active parent or child request running for this instance",
                evidence_type="SQL_QUERY",
                query_template="SELECT count(*) FROM fnd_concurrent_requests WHERE phase_code = 'R' AND program LIKE 'MSC%'",
                is_mandatory=False,
                weight=0.20,
            ),
        ],
        competing_hypotheses=[
            "Another collections run is genuinely in-flight and active",
            "Database link ping timeout during instance registration handshake",
        ],
        missing_evidence_indicators=[
            "FND_CONCURRENT_REQUESTS query for active request IDs",
            "v$session check for active MSC concurrent programs",
        ],
        safe_next_checks=[
            "Verify whether any concurrent request is running for instance 1001",
            "Check if previous request crashed or completed with Error",
        ],
        remediation_spec=RemediationSpec(
            action_name="RESET_REGISTRY",
            risk_tier=RiskTier.HIGH,
            requires_approval=True,
            requires_dry_run=True,
            description="Reset MSC_APPS_INSTANCES.ST_STATUS registry flag to 0 (IDLE).",
            recommended_sql="UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = {instance_id}; COMMIT;",
            preconditions=[
                "Confirm that no active concurrent request is running for instance ID",
            ],
            rollback_plan="UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 2 WHERE INSTANCE_ID = {instance_id}; COMMIT;",
            verification_check="SELECT st_status FROM msc_apps_instances WHERE instance_id = :inst_id",
        ),
    ),

    # 11. Baseline Healthy Pipeline Run
    "RULE_HEALTHY_BASELINE": DiagnosticRule(
        rule_id="RULE_HEALTHY_BASELINE",
        domain=FailureDomain.HEALTHY_BASELINE,
        primary_code="HEALTHY",
        title="Baseline Healthy ASCP Collections Pipeline Execution",
        subsystem="Stage 3: Staging Maintenance & Purge (MSCPDCP)",
        severity=IncidentSeverity.INFO,
        summary="All ETL stages completed successfully with zero lock contention, valid surrogate keys, and normal registry status.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-COMPLETED",
                description="All stages log successful completion",
                evidence_type="LOG_PATTERN",
                required_match="completed successfully",
                is_mandatory=True,
                weight=0.50,
            ),
            EvidenceSignature(
                code="EV-REGISTRY-ZERO",
                description="ST_STATUS reports 0 (IDLE / STAGING_PREPARED)",
                evidence_type="REGISTRY_STATE",
                required_match="ST_STATUS = 0",
                is_mandatory=True,
                weight=0.50,
            ),
        ],
        competing_hypotheses=[],
        missing_evidence_indicators=[],
        safe_next_checks=[
            "Verify plan generation in Advanced Supply Chain Planning planner workbench",
        ],
        remediation_spec=RemediationSpec(
            action_name="INSPECT_LOCKS",
            risk_tier=RiskTier.LOW,
            requires_approval=False,
            requires_dry_run=False,
            description="Read-only status introspection. No remediation required.",
            recommended_sql=None,
            preconditions=[],
            rollback_plan="No action taken.",
            verification_check="SELECT 1 FROM DUAL",
        ),
    ),

    # 12. Resource Capacity Bottleneck & Overload
    "RULE_RESOURCE_CAPACITY_OVERLOAD": DiagnosticRule(
        rule_id="RULE_RESOURCE_CAPACITY_OVERLOAD",
        domain=FailureDomain.RESOURCE_CAPACITY_BOTTLENECK,
        primary_code="RESOURCE_OVERLOAD",
        title="Manufacturing Work Center Capacity Bottleneck & Overload",
        subsystem="Stage 4: Memory-based Planner (MSRCS)",
        severity=IncidentSeverity.HIGH,
        summary="Required machine or labor hours exceed available capacity in department work center, causing pegged supply delays.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-CAPACITY",
                description="Resource overload detected in planner log",
                evidence_type="LOG_PATTERN",
                required_match="Resource overload",
                is_mandatory=True,
                weight=0.50,
            ),
            EvidenceSignature(
                code="EV-OVERLOAD-HOURS",
                description="Overload hours reported in planning exception",
                evidence_type="LOG_PATTERN",
                required_match="overload hours",
                is_mandatory=True,
                weight=0.30,
            ),
            EvidenceSignature(
                code="EV-RESOURCE-AVAIL-V",
                description="msc_net_resource_avail_v confirms required hours > available hours",
                evidence_type="SQL_QUERY",
                query_template="SELECT * FROM msc_net_resource_avail_v WHERE required_hours > available_hours",
                is_mandatory=False,
                weight=0.20,
            ),
        ],
        competing_hypotheses=[
            "Shop floor resource downtime calendar not synchronized to ASCP ODS",
            "Simultaneous batch release of unconstrained work orders",
        ],
        missing_evidence_indicators=[
            "Work center department resource calendar shifts",
            "Alternate routing definitions for affected items",
        ],
        safe_next_checks=[
            "Inspect MSC_DEPARTMENT_RESOURCES for shift calendar definitions",
            "Verify alternate work centers in MSC_ROUTING_OPERATIONS",
        ],
        remediation_spec=RemediationSpec(
            action_name="INSPECT_LOCKS",
            risk_tier=RiskTier.LOW,
            requires_approval=False,
            requires_dry_run=False,
            description="Planner advisory finding: Work center capacity overloaded. Rebalance shifts or allocate alternate routing.",
            recommended_sql=None,
            preconditions=[],
            rollback_plan="No action taken.",
            verification_check="SELECT 1 FROM DUAL",
        ),
    ),

    # 13. Sourcing Rule Circular Loop
    "RULE_SOURCING_CIRCULAR_LOOP": DiagnosticRule(
        rule_id="RULE_SOURCING_CIRCULAR_LOOP",
        domain=FailureDomain.SOURCING_RULES_MASTER_DATA,
        primary_code="SOURCING_LOOP",
        title="Circular Sourcing Rule Loop in Supply Chain Network",
        subsystem="Stage 5: Supply-Demand Allocation & Sourcing",
        severity=IncidentSeverity.HIGH,
        summary="Circular transfer sourcing rule detected between organizations, resulting in infinite replenishment loop.",
        evidence_signatures=[
            EvidenceSignature(
                code="EV-LOG-SOURCING-LOOP",
                description="Sourcing loop logged during supply allocation",
                evidence_type="LOG_PATTERN",
                required_match="Sourcing loop",
                is_mandatory=True,
                weight=0.50,
            ),
            EvidenceSignature(
                code="EV-SOURCING-ITEMS",
                description="Specific item and organization loop identifiers",
                evidence_type="LOG_PATTERN",
                required_match="between Org",
                is_mandatory=True,
                weight=0.30,
            ),
            EvidenceSignature(
                code="EV-MRP-SOURCING-RULES",
                description="mrp_sourcing_rules verification query",
                evidence_type="SQL_QUERY",
                query_template="SELECT * FROM mrp_sources_v WHERE source_organization_id = organization_id",
                is_mandatory=False,
                weight=0.20,
            ),
        ],
        competing_hypotheses=[
            "Assignment set hierarchy precedence conflict (Item-Org overriding Global)",
            "Incorrect rank weighting between primary and backup suppliers",
        ],
        missing_evidence_indicators=[
            "MRP_ASSIGNMENT_SETS active hierarchy definition",
            "Effective date ranges on sourcing rule transfer splits",
        ],
        safe_next_checks=[
            "Inspect MRP_SR_RECEIPT_ORG and MRP_SR_SOURCE_ORG definitions",
            "Check sourcing rule assignment set priorities",
        ],
        remediation_spec=RemediationSpec(
            action_name="INSPECT_LOCKS",
            risk_tier=RiskTier.LOW,
            requires_approval=False,
            requires_dry_run=False,
            description="Planner advisory finding: Circular sourcing rule. Deactivate invalid transfer rule in source ERP.",
            recommended_sql=None,
            preconditions=[],
            rollback_plan="No action taken.",
            verification_check="SELECT 1 FROM DUAL",
        ),
    ),
}


def lookup_diagnostic_rule(error_signature: str) -> DiagnosticRule | None:
    """Find matching diagnostic rule by ORA code, keyword, or rule ID."""
    sig = error_signature.upper().strip()
    for rule in ASCP_KNOWLEDGE_RULES.values():
        if rule.primary_code.upper() in sig or rule.rule_id.upper() in sig or rule.title.upper() in sig:
            return rule
    return None


def get_rules_for_domain(domain: FailureDomain) -> list[DiagnosticRule]:
    """Retrieve all diagnostic rules under a specific failure domain."""
    return [r for r in ASCP_KNOWLEDGE_RULES.values() if r.domain == domain]
