"""Real-Time Oracle Lock Diagnostics Engine.
Direct introspection of V$SESSION, V$LOCK, V$LOCKED_OBJECT, DBA_OBJECTS, and V$SQL.
Executes hierarchical lock queries to isolate root blocker sessions holding Mode 6 locks
on ASCP staging tables (MSC_ST_*).
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass
from typing import Any

logger = logging.getLogger(__name__)

class LockQueryError(Exception):
    """Raised when live Oracle lock query fails."""

LOCK_MODE_MAPPING = {
    0: ("NONE", "Lock requested but not yet obtained. Worker queued waiting on target table."),
    1: ("NULL", "Null structural lock. Zero impact on parallel pull/load workers."),
    2: ("ROWS_S (SS)", "Row Share Lock. Permits concurrent DML; allows MSCPDPW workers to insert into staging."),
    3: ("ROW_X (SX)", "Row Exclusive Table Lock. Standard DML lock; permits concurrent DML but blocks exclusive table lock."),
    4: ("SHARE (S)", "Share Table Lock. Prevents concurrent table updates; halts MSCPDCW worker ODS transformations."),
    5: ("S/ROW-X (SSX)", "Share Row Exclusive Table Lock. Blocks concurrent row updates & table locks; halts parallel load workers."),
    6: ("Exclusive (X)", "Exclusive Table Lock. Completely blocks MSCPDCP staging truncations and parallel worker writes.")
}

HIERARCHICAL_LOCK_SQL_V = """SELECT
    LEVEL AS lock_depth,
    CONNECT_BY_ISLEAF AS is_blocked_leaf,
    1 AS inst_id,
    s.sid,
    s.serial# AS serial_number,
    s.username AS oracle_username,
    s.osuser AS os_user_name,
    s.process AS os_process_id,
    s.module,
    s.action,
    s.blocking_session,
    lo.object_id,
    do.object_name,
    lo.locked_mode,
    sq.sql_text AS current_sql_text
FROM v$session s
LEFT JOIN v$locked_object lo ON s.sid = lo.session_id
LEFT JOIN dba_objects do     ON lo.object_id = do.object_id
LEFT JOIN v$sql sq           ON s.sql_id = sq.sql_id
WHERE s.module LIKE '%MSC%'
   OR s.blocking_session IS NOT NULL
   OR s.sid IN (SELECT blocking_session FROM v$session WHERE blocking_session IS NOT NULL)
   OR s.sid IN (SELECT session_id FROM v$locked_object WHERE locked_mode >= 3)
CONNECT BY PRIOR s.sid = s.blocking_session
START WITH s.blocking_session IS NULL
       AND (
           s.sid IN (SELECT blocking_session FROM v$session WHERE blocking_session IS NOT NULL)
           OR s.sid IN (SELECT session_id FROM v$locked_object WHERE locked_mode >= 3)
       )
ORDER BY LEVEL ASC;"""

HIERARCHICAL_LOCK_SQL_GV = """SELECT
    LEVEL AS lock_depth,
    CONNECT_BY_ISLEAF AS is_blocked_leaf,
    s.inst_id,
    s.sid,
    s.serial# AS serial_number,
    s.username AS oracle_username,
    s.osuser AS os_user_name,
    s.process AS os_process_id,
    s.module,
    s.action,
    s.blocking_session,
    lo.object_id,
    do.object_name,
    lo.locked_mode,
    sq.sql_text AS current_sql_text
FROM gv$session s
LEFT JOIN gv$locked_object lo ON s.sid = lo.session_id AND s.inst_id = lo.inst_id
LEFT JOIN dba_objects do      ON lo.object_id = do.object_id
LEFT JOIN gv$sql sq           ON s.sql_id = sq.sql_id AND s.inst_id = sq.inst_id
WHERE s.module LIKE '%MSC%'
   OR s.blocking_session IS NOT NULL
   OR s.sid IN (SELECT blocking_session FROM gv$session WHERE blocking_session IS NOT NULL)
   OR s.sid IN (SELECT session_id FROM gv$locked_object WHERE locked_mode >= 3)
CONNECT BY PRIOR s.sid = s.blocking_session
START WITH s.blocking_session IS NULL
       AND (
           s.sid IN (SELECT blocking_session FROM gv$session WHERE blocking_session IS NOT NULL)
           OR s.sid IN (SELECT session_id FROM gv$locked_object WHERE locked_mode >= 3)
       )
ORDER BY LEVEL ASC;"""

HIERARCHICAL_LOCK_SQL = HIERARCHICAL_LOCK_SQL_V

FALLBACK_LOCK_SQL_V = """SELECT
    1 AS lock_depth,
    0 AS is_blocked_leaf,
    1 AS inst_id,
    s.sid,
    s.serial# AS serial_number,
    s.username AS oracle_username,
    s.osuser AS os_user_name,
    s.process AS os_process_id,
    s.module,
    s.action,
    s.blocking_session,
    lo.object_id,
    do.object_name,
    lo.locked_mode,
    sq.sql_text AS current_sql_text
FROM v$locked_object lo
JOIN v$session s ON lo.session_id = s.sid
LEFT JOIN dba_objects do ON lo.object_id = do.object_id
LEFT JOIN v$sql sq ON s.sql_id = sq.sql_id
ORDER BY lo.locked_mode DESC"""

FALLBACK_LOCK_SQL_GV = """SELECT
    1 AS lock_depth,
    0 AS is_blocked_leaf,
    s.inst_id,
    s.sid,
    s.serial# AS serial_number,
    s.username AS oracle_username,
    s.osuser AS os_user_name,
    s.process AS os_process_id,
    s.module,
    s.action,
    s.blocking_session,
    lo.object_id,
    do.object_name,
    lo.locked_mode,
    sq.sql_text AS current_sql_text
FROM gv$locked_object lo
JOIN gv$session s ON lo.session_id = s.sid AND lo.inst_id = s.inst_id
LEFT JOIN dba_objects do ON lo.object_id = do.object_id
LEFT JOIN gv$sql sq ON s.sql_id = sq.sql_id AND s.inst_id = sq.inst_id
ORDER BY lo.locked_mode DESC"""

SQL_QUERY_REGISTRY: dict[str, str] = {
    "HIERARCHICAL_LOCK_TREE": HIERARCHICAL_LOCK_SQL_V,
    "HIERARCHICAL_LOCK_TREE_RAC": HIERARCHICAL_LOCK_SQL_GV,
    "ORA_00054_LOCK_LOOKUP": (
        "SELECT lo.session_id AS sid, s.serial#, 1 AS inst_id, lo.locked_mode, do.object_name "
        "FROM v$locked_object lo "
        "JOIN dba_objects do ON lo.object_id = do.object_id "
        "JOIN v$session s ON lo.session_id = s.sid "
        "WHERE do.object_name LIKE :table_pattern"
    ),
    "ORA_00054_LOCK_LOOKUP_RAC": (
        "SELECT lo.session_id AS sid, s.serial#, s.inst_id, lo.locked_mode, do.object_name "
        "FROM gv$locked_object lo "
        "JOIN dba_objects do ON lo.object_id = do.object_id "
        "JOIN gv$session s ON lo.session_id = s.sid AND lo.inst_id = s.inst_id "
        "WHERE do.object_name LIKE :table_pattern"
    ),
    "ST_STATUS_REGISTRY_CHECK": (
        "SELECT instance_id, instance_code, st_status, last_collection_date "
        "FROM msc_apps_instances WHERE instance_id = :instance_id"
    ),
    "SESSION_UNDO_VOLUME_CHECK": (
        "SELECT s.sid, s.serial#, 1 AS inst_id, t.used_urec, t.used_ublk, t.start_time "
        "FROM v$session s "
        "JOIN v$transaction t ON s.taddr = t.addr "
        "WHERE s.sid = :sid"
    ),
    "SESSION_UNDO_VOLUME_CHECK_RAC": (
        "SELECT s.sid, s.serial#, s.inst_id, t.used_urec, t.used_ublk, t.start_time "
        "FROM gv$session s "
        "JOIN gv$transaction t ON s.taddr = t.addr AND s.inst_id = t.inst_id "
        "WHERE s.sid = :sid"
    ),
    "ORA_14098_INDEX_CHECK": (
        "SELECT index_name, partition_name, status "
        "FROM dba_ind_partitions WHERE table_name = :table_name"
    ),
    "DBMS_PIPE_STATUS_CHECK": (
        "SELECT name, maxsize, current_size "
        "FROM v$db_pipes WHERE name LIKE 'MSC_PIPE_%'"
    ),
    "KILL_SESSION": "ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE;",
    "PURGE_STAGING": "BEGIN MSC_CL_COLLECTION.PURGE_STAGING_TABLES_SUB(p_instance_id => :instance_id, p_validation => 'N'); END;",
    "RESET_REGISTRY": "UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = :instance_id; COMMIT;",
    "ALIGN_INDEXES": "EXEC MSC_CL_EXCHANGE_PARTTN.ALIGN_INDEX_DEFS('{table_name}');",
    "PURGE_PIPE": "EXEC DBMS_PIPE.PURGE('MSC_PIPE_{inst}');",
    "REFRESH_SNAPSHOT": "EXEC DBMS_SNAPSHOT.REFRESH('{mview_name}', 'F');",
    "DEADLOCK_TRACE_CHECK": "SELECT inst_id, sid, serial#, username, status, sql_id FROM gv$session WHERE status = 'ACTIVE';",
    "UNDO_RETENTION_CHECK": "SELECT tablespace_name, status, retention FROM dba_tablespaces WHERE contents = 'UNDO';",
    "TABLESPACE_QUOTA_CHECK": "SELECT tablespace_name, bytes/1024/1024 as mbytes FROM dba_data_files WHERE tablespace_name = :tablespace_name;",
    "SHARED_POOL_FREE_CHECK": "SELECT pool, name, bytes/1024/1024 as mbytes FROM v$sgastat WHERE pool = 'shared pool' AND name = 'free memory';",
    "FLUSH_SHARED_POOL": "ALTER SYSTEM FLUSH SHARED_POOL;",
    "EXTEND_TABLESPACE": "ALTER TABLESPACE {tablespace_name} ADD DATAFILE SIZE 100M AUTOEXTEND ON NEXT 50M;",
    "EXTEND_UNDO_RETENTION": "ALTER SYSTEM SET UNDO_RETENTION = 10800 SCOPE=BOTH;"
}

def get_sql_query(query_id: str, **kwargs) -> str:
    """Retrieve SQL query template by identifier, optionally formatting with parameters."""
    raw = SQL_QUERY_REGISTRY.get(query_id, "")
    if kwargs and raw:
        return raw.format(**kwargs)
    return raw

from ascp_agent.db import OracleConnectionPool, get_oracle_pool


@dataclass
class LockTelemetryItem:
    lock_depth: int
    is_blocked_leaf: int
    sid: int
    serial_number: int
    oracle_username: str
    os_user_name: str
    os_process_id: str
    module: str
    action: str
    blocking_session: int | None
    object_id: int | None
    object_name: str
    locked_mode: int
    locked_mode_text: str
    operational_impact: str
    current_sql_text: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class LockDiagnosticsEngine:
    """Interrogates Oracle dynamic performance views to uncover root blocker sessions."""

    def __init__(
        self,
        connection_config: Any | None = None,
        simulated_scenario: str | None = None,
        pool: OracleConnectionPool | None = None,
        config: Any | None = None,
    ):
        self.config = config or connection_config
        self.simulated_scenario = simulated_scenario
        cfg = self.config if hasattr(self.config, "host") else None
        self.pool: OracleConnectionPool = pool if pool is not None else get_oracle_pool(cfg)
        self._cached_telemetry: list[dict[str, Any]] | None = None
        self._cache_timestamp: float = 0.0
        self.cache_ttl: float = 5.0

    async def get_async_pool(self):
        """Initializes or returns python-oracledb asynchronous connection pool in thin mode."""
        if not self.pool.is_simulation:
            await self.pool.initialize_async_pool()
            return self.pool._async_pool
        return None

    def _row_to_item(self, row_dict: dict[str, Any]) -> dict[str, Any]:
        """Convert a single database row dict into a LockTelemetryItem dict."""
        locked_mode = row_dict.get("locked_mode", 0) or 0
        mode_text, impact = LOCK_MODE_MAPPING.get(locked_mode, ("UNKNOWN", "Undefined mode."))
        item = LockTelemetryItem(
            lock_depth=row_dict.get("lock_depth", 1),
            is_blocked_leaf=row_dict.get("is_blocked_leaf", 1),
            sid=row_dict.get("sid", 0),
            serial_number=row_dict.get("serial_number", 0),
            oracle_username=row_dict.get("oracle_username", "APPS"),
            os_user_name=row_dict.get("os_user_name", "applmgr"),
            os_process_id=str(row_dict.get("os_process_id", "")),
            module=row_dict.get("module", ""),
            action=row_dict.get("action", ""),
            blocking_session=row_dict.get("blocking_session"),
            object_id=row_dict.get("object_id"),
            object_name=row_dict.get("object_name", "UNKNOWN"),
            locked_mode=locked_mode,
            locked_mode_text=mode_text,
            operational_impact=impact,
            current_sql_text=row_dict.get("current_sql_text", "")
        )
        return item.to_dict()

    def _map_query_rows(self, dict_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Maps raw row dictionaries to structured LockTelemetryItem dictionaries."""
        return [self._row_to_item(r) for r in dict_rows]

    def _query_live_oracle(self) -> list[dict[str, Any]]:
        """Run the hierarchical lock query against live Oracle. Raises on failure."""
        results: list[dict[str, Any]] = []
        oracledb_mod = getattr(self.pool, "_oracledb", None)
        if oracledb_mod is None:
            import importlib
            oracledb_mod = importlib.import_module("oracledb")
        cfg = self.config or getattr(self.pool, "config", None)
        target_host = getattr(cfg, "scan_address", None) or cfg.host
        is_rac = bool(getattr(cfg, "is_rac", False))
        with oracledb_mod.connect(
            user=cfg.username,
            password=cfg.password,
            host=target_host,
            port=cfg.port,
            service_name=cfg.service_name,
        ) as conn, conn.cursor() as cursor:
            # Query hierarchical locks: try RAC GV$ if configured, with automatic fallback to single-instance V$ on ORA-00942
            primary_sql = HIERARCHICAL_LOCK_SQL_GV if is_rac else HIERARCHICAL_LOCK_SQL_V
            fallback_sql = HIERARCHICAL_LOCK_SQL_V if is_rac else HIERARCHICAL_LOCK_SQL_GV
            try:
                cursor.execute(primary_sql)
            except Exception as exc:
                if "ORA-00942" in str(exc):
                    logger.info("GV$ view not available (ORA-00942); falling back to localized V$ view.")
                    cursor.execute(fallback_sql)
                else:
                    raise

            cols = [c[0].lower() for c in cursor.description]
            for row in cursor.fetchall():
                results.append(self._row_to_item(dict(zip(cols, row))))

            if not results:
                # Direct fallback for ORA-00054 where the victim errored NOWAIT and is no longer queued
                primary_fb = FALLBACK_LOCK_SQL_GV if is_rac else FALLBACK_LOCK_SQL_V
                secondary_fb = FALLBACK_LOCK_SQL_V if is_rac else FALLBACK_LOCK_SQL_GV
                try:
                    cursor.execute(primary_fb)
                except Exception as exc:
                    if "ORA-00942" in str(exc):
                        cursor.execute(secondary_fb)
                    else:
                        raise
                cols = [c[0].lower() for c in cursor.description]
                for row in cursor.fetchall():
                    results.append(self._row_to_item(dict(zip(cols, row))))
        return results

    async def execute_hierarchical_lock_query_async(self) -> list[dict[str, Any]]:
        """Executes non-blocking async hierarchical query via live query or simulation."""
        if not self.pool.is_simulation:
            try:
                return self._query_live_oracle()
            except Exception as exc:
                logger.exception("Live lock query failed")
                raise LockQueryError("Live Oracle lock query failed") from exc
        if not self.simulated_scenario:
            logger.info("LockDiagnosticsEngine: simulation mode with no scenario specified. Returning empty telemetry.")
            return []
        return self._generate_simulated_lock_telemetry()

    def execute_hierarchical_lock_query(self, bypass_cache: bool = False) -> list[dict[str, Any]]:
        """Executes hierarchical query or returns TTL-cached telemetry to prevent database hammering."""
        now = time.time()
        if not bypass_cache and self._cached_telemetry is not None and (now - self._cache_timestamp) < self.cache_ttl:
            return self._cached_telemetry

        if not self.pool.is_simulation:
            try:
                mapped = self._query_live_oracle()
                self._cached_telemetry = mapped
                self._cache_timestamp = now
                return mapped
            except Exception as exc:
                logger.exception("Live lock query failed")
                raise LockQueryError("Live Oracle lock query failed") from exc

        if not self.simulated_scenario:
            logger.info("LockDiagnosticsEngine: simulation mode with no scenario specified. Returning empty telemetry.")
            self._cached_telemetry = []
            self._cache_timestamp = now
            return []

        res = self._generate_simulated_lock_telemetry()
        self._cached_telemetry = res
        self._cache_timestamp = now
        return res

    def _generate_simulated_lock_telemetry(self) -> list[dict[str, Any]]:
        """Simulate hierarchical lock scenarios for ASCP collections."""
        if self.simulated_scenario == "ora_00054_mode6":
            # Scenario: Uncommitted DML / manual LOCK TABLE holding Mode 6 on MSC_ST_DEMANDS
            root_mode_text, root_impact = LOCK_MODE_MAPPING[6]
            blocked_mode_text, blocked_impact = LOCK_MODE_MAPPING[0]

            root_blocker = LockTelemetryItem(
                lock_depth=1,
                is_blocked_leaf=0,
                sid=412,
                serial_number=28419,
                oracle_username="APPS",
                os_user_name="applmgr",
                os_process_id="28419",
                module="SQL*Plus",
                action="MANUAL_MAINTENANCE",
                blocking_session=None,
                object_id=89234,
                object_name="MSC_ST_DEMANDS",
                locked_mode=6,
                locked_mode_text=root_mode_text,
                operational_impact=root_impact,
                current_sql_text="LOCK TABLE MSC_ST_DEMANDS IN EXCLUSIVE MODE NOWAIT"
            )

            blocked_worker_1 = LockTelemetryItem(
                lock_depth=2,
                is_blocked_leaf=1,
                sid=528,
                serial_number=19204,
                oracle_username="APPS",
                os_user_name="applmgr",
                os_process_id="31902",
                module="MSCPDCW",
                action="ODS_LOAD_DEMANDS_WORKER_1",
                blocking_session=412,
                object_id=89234,
                object_name="MSC_ST_DEMANDS",
                locked_mode=0,
                locked_mode_text=blocked_mode_text,
                operational_impact=blocked_impact,
                current_sql_text="INSERT /*+ APPEND */ INTO MSC_DEMANDS (PLAN_ID, ...) SELECT -1, ... FROM MSC_ST_DEMANDS"
            )

            blocked_worker_2 = LockTelemetryItem(
                lock_depth=2,
                is_blocked_leaf=1,
                sid=529,
                serial_number=19215,
                oracle_username="APPS",
                os_user_name="applmgr",
                os_process_id="31905",
                module="MSCPDCW",
                action="ODS_LOAD_DEMANDS_WORKER_2",
                blocking_session=412,
                object_id=89234,
                object_name="MSC_ST_DEMANDS",
                locked_mode=0,
                locked_mode_text=blocked_mode_text,
                operational_impact=blocked_impact,
                current_sql_text="UPDATE MSC_ST_DEMANDS SET PROCESS_STATUS = 2 WHERE PROCESS_STATUS = 1"
            )

            return [root_blocker.to_dict(), blocked_worker_1.to_dict(), blocked_worker_2.to_dict()]

        elif self.simulated_scenario == "ora_00060_deadlock":
            # Scenario: Cross-worker circular lock wait on staging tables
            root_mode_text, root_impact = LOCK_MODE_MAPPING[6]
            blocked_mode_text, blocked_impact = LOCK_MODE_MAPPING[0]

            deadlock_blocker = LockTelemetryItem(
                lock_depth=1,
                is_blocked_leaf=0,
                sid=142,
                serial_number=31289,
                oracle_username="APPS",
                os_user_name="applmgr",
                os_process_id="31289",
                module="MSCPDCW",
                action="ODS_LOAD_BOM",
                blocking_session=None,
                object_id=89230,
                object_name="MSC_ST_BOM",
                locked_mode=6,
                locked_mode_text=root_mode_text,
                operational_impact=root_impact,
                current_sql_text="UPDATE MSC_ST_BOM SET PROCESS_STATUS = 2 WHERE INVENTORY_ITEM_ID = :1"
            )

            deadlock_victim = LockTelemetryItem(
                lock_depth=2,
                is_blocked_leaf=1,
                sid=528,
                serial_number=19204,
                oracle_username="APPS",
                os_user_name="applmgr",
                os_process_id="31902",
                module="MSCPDCW",
                action="ODS_LOAD_ROUTINGS",
                blocking_session=142,
                object_id=89231,
                object_name="MSC_ST_ROUTINGS",
                locked_mode=0,
                locked_mode_text=blocked_mode_text,
                operational_impact=blocked_impact,
                current_sql_text="UPDATE MSC_ST_ROUTINGS SET PROCESS_STATUS = 2 WHERE ROUTING_SEQUENCE_ID = :1"
            )

            return [deadlock_blocker.to_dict(), deadlock_victim.to_dict()]

        elif self.simulated_scenario == "no_locks":
            return []

        return []

    def isolate_root_blocker(self, telemetry: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Identify root blocker session from hierarchical telemetry."""
        candidates = [
            item for item in telemetry
            if item.get("lock_depth") == 1 and item.get("blocking_session") is None
        ]
        if not candidates:
            return None
        return max(
            candidates,
            key=lambda c: (
                c.get("locked_mode", 0) or 0,
                1 if c.get("is_blocked_leaf") == 0 else 0,
            ),
        )

    def inspect_session_undo_volume(self, sid: int) -> dict[str, Any]:
        """Inspects V$TRANSACTION (USED_UREC) for active uncommitted rollback volume.
        Prevents PMON rollback hang where held locks persist while un-abortable rollback executes.
        """
        if not self.pool.is_simulation:
            cfg = self.config or getattr(self.pool, "config", None)
            is_rac = bool(getattr(cfg, "is_rac", False))
            sql_rac = SQL_QUERY_REGISTRY["SESSION_UNDO_VOLUME_CHECK_RAC"]
            sql_v = SQL_QUERY_REGISTRY["SESSION_UNDO_VOLUME_CHECK"]
            primary = sql_rac if is_rac else sql_v
            fallback = sql_v if is_rac else sql_rac
            try:
                try:
                    res = self.pool.execute_query(primary, {"sid": sid})
                except Exception as exc:
                    if "ORA-00942" in str(exc):
                        res = self.pool.execute_query(fallback, {"sid": sid})
                    else:
                        raise
                records = res.to_dicts()
                if records:
                    used_urec = records[0].get("used_urec", 0) or 0
                else:
                    used_urec = 0
            except Exception as exc:
                logger.exception("Live query to V$TRANSACTION failed for SID %s", sid)
                raise LockQueryError(f"Live undo-volume query failed for SID {sid}") from exc
        else:
            if sid == 999:  # High transaction volume scenario
                used_urec = 150000
            else:
                used_urec = 420  # Standard low transaction volume
        
        high_risk = used_urec > 50000
        estimated_rollback_sec = round(used_urec * 0.0003, 1)

        return {
            "sid": sid,
            "used_urec": used_urec,
            "high_rollback_risk": high_risk,
            "estimated_rollback_sec": estimated_rollback_sec,
            "recommendation": "DEFER_KILL_ALERT_DBA" if high_risk else "PROCEED_WITH_TERMINATION"
        }

    def verify_session_active(self, sid: int, serial: int, inst_id: int | None = None) -> dict[str, Any] | None:
        """Re-queries the database immediately prior to termination to confirm the session
        is still active and that the SID has not been recycled for a new connection.
        Queries global GV$SESSION view across all RAC nodes concurrently validating SID and SERIAL#.
        """
        if sid <= 0 or serial <= 0:
            return None

        if not self.pool.is_simulation:
            cfg = self.config or getattr(self.pool, "config", None)
            is_rac = bool(getattr(cfg, "is_rac", False)) or (inst_id is not None)
            if inst_id is not None:
                sql_rac = (
                    "SELECT s.inst_id, s.sid, s.serial#, s.status, s.username "
                    "FROM gv$session s "
                    "WHERE s.sid = :sid AND s.serial# = :serial AND s.inst_id = :inst_id"
                )
                params_rac = {"sid": sid, "serial": serial, "inst_id": inst_id}
            else:
                sql_rac = (
                    "SELECT s.inst_id, s.sid, s.serial#, s.status, s.username "
                    "FROM gv$session s "
                    "WHERE s.sid = :sid AND s.serial# = :serial"
                )
                params_rac = {"sid": sid, "serial": serial}

            sql_v = (
                "SELECT 1 AS inst_id, s.sid, s.serial#, s.status, s.username "
                "FROM v$session s "
                "WHERE s.sid = :sid AND s.serial# = :serial"
            )
            params_v = {"sid": sid, "serial": serial}

            query_pri, params_pri = (sql_rac, params_rac) if is_rac else (sql_v, params_v)
            query_sec, params_sec = (sql_v, params_v) if is_rac else (sql_rac, params_rac)
            try:
                try:
                    res = self.pool.execute_query(query_pri, params_pri)
                except Exception as exc:
                    if "ORA-00942" in str(exc):
                        res = self.pool.execute_query(query_sec, params_sec)
                    else:
                        raise
                records = res.to_dicts()
                if records and records[0].get("status") != "KILLED":
                    return records[0]
                return None
            except Exception as exc:
                logger.exception("Failed to verify active session status for SID %s", sid)
                raise LockQueryError(f"Session active verification failed for SID {sid}") from exc

        # Simulated mode: verify SID/serial consistency
        if sid == 412 and serial not in (28419, 18920):
            return None
        return {"sid": sid, "serial#": serial, "status": "ACTIVE", "username": "APPS", "inst_id": inst_id or 1}
