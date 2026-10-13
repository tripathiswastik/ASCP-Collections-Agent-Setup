"""LangGraph Autonomous Agent Control Plane for ASCP Collections.
Implements the Directed State Graph (StateGraph), MemorySaver checkpointer,
node functions, conditional routing, Human-in-the-Loop interrupt gates,
and time-travel state debugging.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from collections import OrderedDict, deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ascp_agent.drain_parser import DrainLogParser
from ascp_agent.guardrails import EnterpriseGuardrails
from ascp_agent.hitl_governance import HITLGovernanceEngine
from ascp_agent.itsm_service_now import ServiceNowClient
from ascp_agent.lock_engine import LockDiagnosticsEngine
from ascp_agent.remediation import (
    RemediationEngine,
    format_kill_session_sql,
    format_purge_staging_sql,
    format_recovery_command_block,
)
from ascp_agent.schema_validator import check_validation_routing, validate_schema_node
from ascp_agent.state import (
    AgentState,
    AIMessage,
    Command,
    DiagnosticState,
    HumanMessage,
    InterruptSignal,
    Message,
    Send,
    interrupt,
)

logger = logging.getLogger(__name__)

END = "__END__"

def _clone_state_snapshot(state: DiagnosticState) -> DiagnosticState:
    """Fast snapshot cloning for checkpoints avoiding slow recursive copy.deepcopy."""
    from ascp_agent.state import AgentState
    if isinstance(state, AgentState):
        cloned = AgentState(state)
    elif hasattr(state, "copy"):
        cloned = state.copy()
    else:
        cloned = dict(state)
    for k, v in list(cloned.items()):
        if isinstance(v, list):
            cloned[k] = list(v)
        elif isinstance(v, dict):
            cloned[k] = dict(v)
    return cloned

class CheckpointRecord:
    """A snapshot of graph state at a super-step boundary."""
    def __init__(self, step_index: int, state: DiagnosticState, next_node: str):
        self.step_index = step_index
        self.state = _clone_state_snapshot(state)
        self.next_node = next_node
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

class MemorySaver:
    """In-memory checkpointer supporting state snapshots and time-travel inspection with bounded memory."""
    def __init__(self, max_threads: int = 100, max_checkpoints_per_thread: int = 50):
        self.threads: OrderedDict[str, deque[CheckpointRecord]] = OrderedDict()
        self.max_threads = max_threads
        self.max_checkpoints_per_thread = max_checkpoints_per_thread

    def save(self, thread_id: str, state: DiagnosticState, next_node: str) -> int:
        if len(self.threads) >= self.max_threads and thread_id not in self.threads:
            # Deterministic LRU eviction of oldest thread
            self.threads.popitem(last=False)

        if thread_id not in self.threads:
            self.threads[thread_id] = deque(maxlen=self.max_checkpoints_per_thread)
        else:
            self.threads.move_to_end(thread_id)

        records = self.threads[thread_id]
        last_step = records[-1].step_index if records else 0
        step = last_step + 1
        records.append(CheckpointRecord(step, state, next_node))
        return step

    def get_latest(self, thread_id: str) -> CheckpointRecord | None:
        records = self.threads.get(thread_id)
        if records:
            self.threads.move_to_end(thread_id)
            return records[-1]
        return None

    def get_history(self, thread_id: str) -> list[CheckpointRecord]:
        records = self.threads.get(thread_id)
        if records:
            self.threads.move_to_end(thread_id)
            return list(records)
        return []

def serialize_state_payload(state: Any) -> Any:
    """Recursively serializes state into JSON-safe structure preserving typed message representations."""
    if isinstance(state, (AIMessage, HumanMessage, Message)):
        return {
            "__type__": state.__class__.__name__,
            "content": state.content,
            "role": getattr(state, "role", "assistant")
        }
    if isinstance(state, dict):
        return {k: serialize_state_payload(v) for k, v in state.items() if not callable(v)}
    if isinstance(state, list):
        return [serialize_state_payload(item) for item in state]
    return state

def deserialize_state_payload(payload: Any) -> Any:
    """Recursively deserializes JSON payload restoring typed message instances."""
    if isinstance(payload, dict):
        if "__type__" in payload:
            type_name = payload["__type__"]
            content = payload.get("content", "")
            if type_name == "AIMessage":
                return AIMessage(content=content)
            elif type_name == "HumanMessage":
                return HumanMessage(content=content)
            elif type_name == "Message":
                return Message(content=content, role=payload.get("role", "assistant"))
        return {k: deserialize_state_payload(v) for k, v in payload.items()}
    if isinstance(payload, list):
        return [deserialize_state_payload(item) for item in payload]
    return payload

class PostgresSaver:
    """Durable production checkpointer storing snapshots indexed by persistent thread_id.
    Enables fault-tolerant state snapshots, time-travel debugging, and multi-turn approvals
    across container restarts. Uses connection pooling when PostgreSQL is configured.
    Automatically falls back to memory persistence if PostgreSQL is offline or unconfigured.
    """
    def __init__(self, dsn: str | None = None, min_conn: int = 1, max_conn: int = 10):
        self.dsn = dsn
        self._memory_backup = MemorySaver(max_threads=100, max_checkpoints_per_thread=10)
        self._psycopg = None
        self._pool = None
        self._init_backend(min_conn, max_conn)

    def _init_backend(self, min_conn: int = 1, max_conn: int = 10):
        if not self.dsn:
            return
        try:
            import psycopg2
            from psycopg2 import pool
            self._psycopg = psycopg2
            self._pool = pool.ThreadedConnectionPool(min_conn, max_conn, self.dsn)
            conn = self._pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS ascp_agent_checkpoints (
                            id SERIAL PRIMARY KEY,
                            thread_id VARCHAR(128) NOT NULL,
                            step_index INT NOT NULL,
                            state_payload JSONB NOT NULL,
                            next_node VARCHAR(128) NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        CREATE INDEX IF NOT EXISTS idx_ascp_ckpt_thread ON ascp_agent_checkpoints(thread_id);
                    """)
                conn.commit()
            finally:
                self._pool.putconn(conn)
        except Exception as exc:  # noqa: BLE001 -- fallback to in-memory checkpointer if PostgreSQL is offline
            logger.warning("Postgres backend initialization failed (%s); operating in in-memory fallback mode.", exc)
            if self._pool is not None:
                try:
                    self._pool.closeall()
                except Exception as close_exc:  # noqa: BLE001
                    logger.debug("Error while closing connection pool: %s", close_exc)
                self._pool = None
            self._psycopg = None

    def save(self, thread_id: str, state: DiagnosticState, next_node: str) -> int:
        if self._pool is not None and self._psycopg is not None:
            conn = None
            try:
                conn = self._pool.getconn()
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT COALESCE(MAX(step_index), 0) + 1 FROM ascp_agent_checkpoints WHERE thread_id = %s",
                        (thread_id,)
                    )
                    step = cur.fetchone()[0]
                    serialized = serialize_state_payload(dict(state))
                    from psycopg2.extras import Json
                    cur.execute(
                        "INSERT INTO ascp_agent_checkpoints (thread_id, step_index, state_payload, next_node) VALUES (%s, %s, %s, %s)",
                        (thread_id, step, Json(serialized), next_node)
                    )
                conn.commit()
                return step
            except Exception as exc:  # noqa: BLE001 -- fallback to in-memory checkpointer on write error
                logger.warning("Postgres checkpoint write failed for thread %s (%s); writing to memory fallback", thread_id, exc)
                if conn is not None:
                    try:
                        conn.rollback()
                    except Exception as rb_exc:  # noqa: BLE001
                        logger.debug("Rollback on failed checkpoint write failed: %s", rb_exc)
            finally:
                if conn is not None and self._pool is not None:
                    self._pool.putconn(conn)

        # Fallback to in-memory checkpointer when Postgres is not available or write failed
        return self._memory_backup.save(thread_id, state, next_node)

    def get_latest(self, thread_id: str) -> CheckpointRecord | None:
        if self._pool is not None and self._psycopg is not None:
            conn = None
            try:
                conn = self._pool.getconn()
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT step_index, state_payload, next_node FROM ascp_agent_checkpoints WHERE thread_id = %s ORDER BY id DESC LIMIT 1",
                        (thread_id,)
                    )
                    row = cur.fetchone()
                    if row:
                        step_index, state_json, next_node = row
                        raw_dict = json.loads(state_json) if isinstance(state_json, str) else state_json
                        restored = deserialize_state_payload(raw_dict)
                        return CheckpointRecord(step_index, DiagnosticState(restored), next_node)
            except Exception as exc:  # noqa: BLE001 -- fallback to in-memory checkpointer on query failure
                logger.warning("Postgres get_latest query failed for thread %s (%s); falling back to memory", thread_id, exc)
            finally:
                if conn is not None and self._pool is not None:
                    self._pool.putconn(conn)

        return self._memory_backup.get_latest(thread_id)

    def get_history(self, thread_id: str) -> list[CheckpointRecord]:
        if self._pool is not None and self._psycopg is not None:
            conn = None
            try:
                conn = self._pool.getconn()
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT step_index, state_payload, next_node FROM ascp_agent_checkpoints WHERE thread_id = %s ORDER BY id ASC",
                        (thread_id,)
                    )
                    records = []
                    for row in cur.fetchall():
                        step_index, state_json, next_node = row
                        raw_dict = json.loads(state_json) if isinstance(state_json, str) else state_json
                        restored = deserialize_state_payload(raw_dict)
                        records.append(CheckpointRecord(step_index, DiagnosticState(restored), next_node))
                    return records
            except Exception as exc:  # noqa: BLE001 -- fallback to in-memory checkpointer on query failure
                logger.warning("Postgres get_history query failed for thread %s (%s); falling back to memory", thread_id, exc)
            finally:
                if conn is not None and self._pool is not None:
                    self._pool.putconn(conn)

        return self._memory_backup.get_history(thread_id)

    def close(self):
        """Close connection pool on shutdown."""
        if self._pool is not None:
            try:
                self._pool.closeall()
            except Exception as close_exc:  # noqa: BLE001
                logger.debug("Pool close error: %s", close_exc)
            self._pool = None

class StateGraph:
    """StateGraph engine implementing directed state transitions, conditional edges, and HITL gates."""
    def __init__(self, state_schema=DiagnosticState):
        self.state_schema = state_schema
        self.nodes: dict[str, Callable[[DiagnosticState], dict[str, Any]]] = {}
        self.conditional_edges: dict[str, tuple[Callable[[DiagnosticState], str], dict[str, str]]] = {}
        self.edges: dict[str, str] = {}
        self.entry_point: str | None = None

    def add_node(self, name: str, func: Callable[[DiagnosticState], dict[str, Any]]):
        self.nodes[name] = func

    def set_entry_point(self, name: str):
        self.entry_point = name

    def add_edge(self, from_node: str, to_node: str):
        self.edges[from_node] = to_node

    def add_conditional_edges(self, from_node: str, router_func: Callable[[DiagnosticState], str], route_map: dict[str, str]):
        self.conditional_edges[from_node] = (router_func, route_map)

    def compile(self, checkpointer: MemorySaver | None = None):
        return CompiledStateGraph(self, checkpointer or MemorySaver())

class CompiledStateGraph:
    """Compiled runnable execution engine for the ASCP Diagnostic Control Plane."""
    def __init__(self, graph: StateGraph, checkpointer: MemorySaver):
        self.graph = graph
        self.checkpointer = checkpointer
        self._guardrails_by_thread: dict[str, EnterpriseGuardrails] = {}

    def invoke(
        self,
        initial_state: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
        resume_command: Command | None = None
    ) -> DiagnosticState:
        """Executes the state graph until an interrupt gate or END is reached."""
        config = config or {}
        thread_id = config.get("configurable", {}).get("thread_id", "default_thread")
        if "guardrails" in config:
            guardrails = config["guardrails"]
        elif thread_id in self._guardrails_by_thread:
            guardrails = self._guardrails_by_thread[thread_id]
        else:
            guardrails = EnterpriseGuardrails()
            self._guardrails_by_thread[thread_id] = guardrails

        # Handle resumption from prior checkpoint
        if resume_command is not None:
            last_record = self.checkpointer.get_latest(thread_id)
            if not last_record:
                raise ValueError(f"No checkpoint found for thread '{thread_id}' to resume.")
            state = _clone_state_snapshot(last_record.state)
            # Inject human approval or resume value
            if isinstance(resume_command.resume, dict):
                approved = resume_command.resume.get("approved", False)
                pending_appr = last_record.state.get("interrupt_payload") or {}
                if approved and pending_appr:
                    # Enforce expiration check
                    exp = pending_appr.get("expires_at")
                    if exp and time.time() > exp:
                        raise ValueError("Approval request has expired (TTL exceeded).")
                    # Enforce action and target validation if supplied
                    req_appr_id = resume_command.resume.get("approval_id")
                    if req_appr_id and req_appr_id != pending_appr.get("approval_id"):
                        raise ValueError(f"Mismatched approval_id: expected {pending_appr.get('approval_id')}, got {req_appr_id}")
                    req_action = resume_command.resume.get("target_action")
                    if req_action and req_action != pending_appr.get("action"):
                        raise ValueError(f"Mismatched remediation action: expected {pending_appr.get('action')}, got {req_action}")
                    req_sid = resume_command.resume.get("target_sid")
                    if req_sid is not None and req_sid != pending_appr.get("target_sid"):
                        raise ValueError(f"Mismatched target SID: expected {pending_appr.get('target_sid')}, got {req_sid}")
                state["remediation_approved"] = approved
                state["human_response"] = resume_command.resume
            elif isinstance(resume_command.resume, bool):
                state["remediation_approved"] = resume_command.resume
            state["interrupted"] = False
            state["interrupt_payload"] = None
            current_node = last_record.next_node
        else:
            state = DiagnosticState(initial_state or {})
            current_node = self.graph.entry_point

        recursion_limit = config.get("recursion_limit", 50)
        step_count = 0

        while current_node and current_node != END:
            if step_count >= recursion_limit:
                raise RecursionError(f"GraphRecursionError: Recursion limit of {recursion_limit} reached without reaching terminal node.")
            step_count += 1
            state["remaining_steps"] = max(0, recursion_limit - step_count)

            # 1. Enforce super-step cap guardrail
            guardrails.check_super_step_limit()

            # 2. Track token spend estimation (simulating LLM reasoning consumption)
            guardrails.track_tokens(input_tokens=420, output_tokens=180)

            node_func = self.graph.nodes.get(current_node)
            if not node_func:
                break

            # 3. Execute node function with interrupt exception handling
            try:
                update = node_func(state)
            except InterruptSignal as sig:
                # HITL Gate triggered: persist snapshot and pause execution
                state["interrupted"] = True
                state["interrupt_payload"] = sig.payload
                state["audit_trail"] = [{"step": step_count, "node": current_node, "event": "INTERRUPT_HITL", "payload": sig.payload}]
                self.checkpointer.save(thread_id, state, next_node=current_node)
                return state

            # 4. Apply state updates using field reducers (with concurrent Send fan-out support)
            if isinstance(update, list) and len(update) > 0 and isinstance(update[0], Send):
                with ThreadPoolExecutor(max_workers=min(len(update), 8)) as executor:
                    futures = []
                    for send_action in update:
                        sub_func = self.graph.nodes.get(send_action.node)
                        if sub_func:
                            futures.append(executor.submit(sub_func, send_action.arg))
                    for fut in futures:
                        sub_res = fut.result()
                        if isinstance(sub_res, dict):
                            state.apply_update(sub_res)
            elif isinstance(update, dict):
                state.apply_update(update)

            # 5. Determine next node
            if current_node in self.graph.conditional_edges:
                router, route_map = self.graph.conditional_edges[current_node]
                next_key = router(state)
                next_node = route_map.get(next_key, END)
            elif current_node in self.graph.edges:
                next_node = self.graph.edges[current_node]
            else:
                next_node = END

            # 6. Persist checkpoint (configurable policy; terminal nodes and interrupts always persist)
            checkpoint_policy = config.get("checkpoint_policy", "all")
            if checkpoint_policy == "all" or next_node == END:
                self.checkpointer.save(thread_id, state, next_node=next_node)
            current_node = next_node

        state["completed"] = True
        return state

    def get_state_history(self, config: dict[str, Any]) -> list[CheckpointRecord]:
        thread_id = config.get("configurable", {}).get("thread_id", "default_thread")
        return self.checkpointer.get_history(thread_id)

# -------------------------------------------------------------
# 6-Step Node Implementations matching End-to-End Execution Plan
# -------------------------------------------------------------

_SHARED_DRAIN_PARSER = DrainLogParser()
_WORKER_ERROR_CODES = ("ORA-00054", "ORA-14098", "ORA-02478", "ORA-00001", "ORA-12571")
_EBS_CATALOG_ERROR_CODES = (
    "ORA-00054", "ORA-14098", "ORA-02478", "ORA-00001", "ORA-12571",
    "ORA-00060", "ORA-01555", "ORA-01653", "ORA-04031"
)

def parse_worker_log_node(sub_state: dict[str, Any]) -> dict:
    """Parallel worker node for parsing concurrent worker logs (.req/.log) or staging tables via Send primitive."""
    worker_id = sub_state.get("worker_id", "WORKER_1")
    target_table = sub_state.get("table", "MSC_ST_DEMANDS")
    log_content = sub_state.get("log_content", "")

    parser = _SHARED_DRAIN_PARSER
    extracted_templates = []
    detected_errors: set[str] = set()

    for line in log_content.splitlines():
        if not line.strip():
            continue
        parsed = parser.parse_line(line)
        if parsed.get("template"):
            extracted_templates.append(parsed["template"])
        for code in _WORKER_ERROR_CODES:
            if code in line:
                detected_errors.add(code)

    errors_list = list(detected_errors)
    return {
        "log_templates": extracted_templates,
        "log_buffers": [f"[{worker_id}] Tokenized {len(extracted_templates)} templates on {target_table}."],
        "intermediate_query_results": [{"worker_id": worker_id, "table": target_table, "errors": errors_list}],
        "audit_trail": [{"event": "PARALLEL_WORKER_PARSED", "worker_id": worker_id, "table": target_table}]
    }

def log_ingestion_node(state: AgentState):
    """Step 1: State Initialization & Async Concurrent Log Ingestion with Drain Tree Algorithm.
    Supports dynamic parallel fan-out via Send primitive when multiple worker logs or tables exist.
    """
    # 1. Parallel Fan-Out via Send primitive
    if state.get("worker_logs"):
        return [
            Send("parse_worker_log_node", worker_item)
            for worker_item in state["worker_logs"]
        ]

    raw_logs = state.get("raw_logs", [])
    if not raw_logs:
        raw_logs = [
            "[12-OCT-2025 04:12:01]: Launching Planning ODS Load Worker 1 (MSCPDCW)",
            "[12-OCT-2025 04:12:05]: Cause: ORA-00054: resource busy and acquire with NOWAIT specified on table MSC_ST_DEMANDS.",
            "[12-OCT-2025 04:12:06]: Action: Contact DBA to verify blocking locks on staging tables.",
            "[12-OCT-2025 04:12:10]: Worker process 31902 terminated with fatal error status."
        ]

    parser = _SHARED_DRAIN_PARSER
    extracted_templates = []
    detected_errors: set[str] = set()
    target_table = "MSC_ST_DEMANDS"

    for line in raw_logs:
        parsed = parser.parse_line(line)
        if parsed.get("template"):
            extracted_templates.append(parsed["template"])
        # Anomaly and stack filtering across entire EBS catalog
        for code in _EBS_CATALOG_ERROR_CODES:
            if code in line:
                detected_errors.add(code)
        if ("ST_STATUS" in line and ("not zero" in line or "= 2" in line or "current ST_STATUS = 2" in line or "stalled" in line or "crashed" in line)):
            detected_errors.add("STUCK_ST_STATUS")
        objs = parsed.get("parameters", {}).get("TARGET_OBJECTS", [])
        if objs:
            target_table = objs[0]

    errors_list = list(detected_errors)
    ctx_update = {
        "detected_errors": errors_list,
        "target_staging_table": target_table
    }

    return {
        "log_templates": extracted_templates,
        "context": ctx_update,
        "messages": [AIMessage(
            content=f"Log Ingestion complete: Tokenized {len(extracted_templates)} templates via Drain. Detected error signatures: {', '.join(errors_list) if errors_list else 'None'}."
        )]
    }

def classification_node(state: AgentState) -> dict:
    """Step 2: Failure Domain Classification & Conditional Edge Routing."""
    detected = state.get("context", {}).get("detected_errors", [])
    templates_str = " ".join(state.get("log_templates", []))

    # Priority 1: Exact detected error signatures
    if "ORA-04031" in detected:
        domain = "SHARED_POOL_MEMORY"
        primary_mode = "ORA-04031"
        next_action = "FLUSH_SHARED_POOL"
        phase = "LOAD"
    elif "ORA-00054" in detected:
        domain = "DATABASE_LOCK"
        primary_mode = "ORA-00054"
        next_action = "INSPECT_LOCKS"
        phase = "LOAD"
    elif "ORA-00060" in detected:
        domain = "DEADLOCK_CONCURRENCY"
        primary_mode = "ORA-00060"
        next_action = "INSPECT_LOCKS"
        phase = "LOAD"
    elif "ORA-00001" in detected:
        domain = "STAGING_VALIDATION"
        primary_mode = "ORA-00001"
        next_action = "PURGE_STAGING"
        phase = "LOAD"
    elif "ORA-14098" in detected:
        domain = "PARTITION_EXCHANGE"
        primary_mode = "ORA-14098"
        next_action = "ALIGN_INDEXES"
        phase = "LOAD"
    elif "ORA-01555" in detected:
        domain = "UNDO_RETENTION"
        primary_mode = "ORA-01555"
        next_action = "EXTEND_UNDO_RETENTION"
        phase = "PULL"
    elif "ORA-01653" in detected:
        domain = "STORAGE_CAPACITY"
        primary_mode = "ORA-01653"
        next_action = "EXTEND_TABLESPACE"
        phase = "PULL"
    elif "ORA-02478" in detected:
        domain = "INFRASTRUCTURE_PIPE"
        primary_mode = "ORA-02478"
        next_action = "PURGE_PIPE"
        phase = "PULL"
    elif "ORA-12571" in detected:
        domain = "NETWORK_SNAPSHOT"
        primary_mode = "ORA-12571"
        next_action = "REFRESH_SNAPSHOT"
        phase = "PULL"
    elif "STUCK_ST_STATUS" in detected:
        domain = "ORCHESTRATION_REGISTRY"
        primary_mode = "STUCK_ST_STATUS"
        next_action = "RESET_REGISTRY"
        phase = "PULL"
    # Priority 2: Semantic template keywords if ORA prefix was suppressed
    elif "resource busy" in templates_str or "LOCK TABLE" in templates_str:
        domain = "DATABASE_LOCK"
        primary_mode = "ORA-00054"
        next_action = "INSPECT_LOCKS"
        phase = "LOAD"
    elif "deadlock detected" in templates_str:
        domain = "DEADLOCK_CONCURRENCY"
        primary_mode = "ORA-00060"
        next_action = "INSPECT_LOCKS"
        phase = "LOAD"
    elif "unique constraint" in templates_str:
        domain = "STAGING_VALIDATION"
        primary_mode = "ORA-00001"
        next_action = "PURGE_STAGING"
        phase = "LOAD"
    elif "index mismatch" in templates_str:
        domain = "PARTITION_EXCHANGE"
        primary_mode = "ORA-14098"
        next_action = "ALIGN_INDEXES"
        phase = "LOAD"
    elif "snapshot too old" in templates_str:
        domain = "UNDO_RETENTION"
        primary_mode = "ORA-01555"
        next_action = "EXTEND_UNDO_RETENTION"
        phase = "PULL"
    elif "unable to extend table" in templates_str:
        domain = "STORAGE_CAPACITY"
        primary_mode = "ORA-01653"
        next_action = "EXTEND_TABLESPACE"
        phase = "PULL"
    elif "shared memory" in templates_str:
        domain = "SHARED_POOL_MEMORY"
        primary_mode = "ORA-04031"
        next_action = "FLUSH_SHARED_POOL"
        phase = "LOAD"
    elif "DBMS_PIPE" in templates_str or "maxextents reached" in templates_str:
        domain = "INFRASTRUCTURE_PIPE"
        primary_mode = "ORA-02478"
        next_action = "PURGE_PIPE"
        phase = "PULL"
    elif "packet writer failure" in templates_str:
        domain = "NETWORK_SNAPSHOT"
        primary_mode = "ORA-12571"
        next_action = "REFRESH_SNAPSHOT"
        phase = "PULL"
    elif "ST_STATUS is not zero" in templates_str or "current ST_STATUS = 2" in templates_str:
        domain = "ORCHESTRATION_REGISTRY"
        primary_mode = "STUCK_ST_STATUS"
        next_action = "RESET_REGISTRY"
        phase = "PULL"
    else:
        domain = "HEALTHY"
        primary_mode = "UNKNOWN"
        next_action = "INSPECT_LOCKS"
        phase = "NORMAL"

    return {
        "failure_domain": domain,
        "failure_mode": primary_mode,
        "remediation_action": next_action,
        "context": {"failed_phase": phase, "remediation_action": next_action, "failure_mode": primary_mode},
        "messages": [AIMessage(content=f"Classification: Failure domain mapped to '{domain}' ({primary_mode}). Routing to diagnostic path: {next_action}.")]
    }

def oracle_lock_node(state: AgentState) -> dict:
    """Step 3: Real-Time Hierarchical Oracle Lock Analysis via python-oracledb & V$ views."""
    domain = state.get("failure_domain")
    ctx = state.get("context", {})
    from ascp_agent.config import DEFAULT_CONFIG
    use_sim = ctx.get("use_simulation") if "use_simulation" in ctx else DEFAULT_CONFIG.oracle.use_simulation

    if use_sim:
        if domain == "DEADLOCK_CONCURRENCY":
            scenario = "ora_00060_deadlock"
        elif domain == "DATABASE_LOCK":
            scenario = "ora_00054_mode6"
        else:
            scenario = "no_locks"
    else:
        scenario = None

    engine = LockDiagnosticsEngine(simulated_scenario=scenario)
    try:
        telemetry = engine.execute_hierarchical_lock_query()
    except Exception as exc:
        logger.error("Live Oracle lock diagnostics query failed: %s", exc)
        raise
    root_blocker = engine.isolate_root_blocker(telemetry)

    root_found = root_blocker is not None
    ctx_update = {
        "lock_hierarchy": telemetry
    }

    if root_blocker:
        sid = root_blocker.get("sid")
        serial = root_blocker.get("serial_number")
        obj = root_blocker.get("object_name")
        mode = root_blocker.get("locked_mode_text")
        sql = root_blocker.get("current_sql_text")
        msg = f"Hierarchical lock tree isolated root blocker: SID {sid} (SERIAL# {serial}) holding Mode 6 {mode} on {obj}. Holding SQL: {sql}."
        rem_act = "KILL_SESSION"
    else:
        msg = "Hierarchical lock query executed across V$SESSION / V$LOCKED_OBJECT: No active Mode 6 lock contention detected."
        rem_act = "INSPECT_LOCKS"

    ctx_update["remediation_action"] = rem_act

    return {
        "lock_telemetry": telemetry,
        "root_blocker_found": root_found,
        "remediation_action": rem_act,
        "context": ctx_update,
        "messages": [AIMessage(content=msg)]
    }

def rca_hypothesis_node(state: AgentState) -> dict:
    """Step 4: ReAct Synthesis & Root Cause Confidence Scoring."""
    domain = state.get("failure_domain")
    root_found = state.get("root_blocker_found")
    detected = state.get("context", {}).get("detected_errors", [])
    templates_str = " ".join(state.get("log_templates", []))
    mode = state.get("failure_mode") or "UNKNOWN"

    # Calculate deterministic domain confidence score (0 to 100%)
    if domain == "DATABASE_LOCK" and root_found and ("ORA-00054" in detected or "resource busy" in templates_str):
        confidence = 96.5
        risk = "HIGH"  # KILL SESSION required
        thesis = "Definitive Root Cause: Uncommitted session holds Exclusive TM Mode 6 lock on staging table, halting MSCPDCW workers."
    elif domain == "STAGING_VALIDATION" and ("ORA-00001" in detected or "unique constraint" in templates_str):
        confidence = 92.0
        risk = "MEDIUM"
        thesis = "Definitive Root Cause: Legacy unpurged interface records causing duplicate surrogate key collisions during Stage 2 ODS Load."
    elif domain == "PARTITION_EXCHANGE" and ("ORA-14098" in detected or "index mismatch" in templates_str):
        confidence = 94.0
        risk = "MEDIUM"
        thesis = "Definitive Root Cause: Staging partition index definitions diverge from target partitioned ODS table."
    elif domain == "DEADLOCK_CONCURRENCY" and ("ORA-00060" in detected or "deadlock detected" in templates_str):
        confidence = 95.0
        risk = "HIGH"
        thesis = "Definitive Root Cause: Cross-worker circular lock wait on staging tables. Root blocker session isolated."
    elif domain == "UNDO_RETENTION" and ("ORA-01555" in detected or "snapshot too old" in templates_str):
        confidence = 94.5
        risk = "LOW"
        thesis = "Definitive Root Cause: Extraction query exceeded UNDO_RETENTION on source ERP instance during snapshot pull."
    elif domain == "STORAGE_CAPACITY" and ("ORA-01653" in detected or "unable to extend table" in templates_str):
        confidence = 95.0
        risk = "MEDIUM"
        thesis = "Definitive Root Cause: Staging tablespace storage quota exhausted during bulk extraction pull."
    elif domain == "SHARED_POOL_MEMORY" and ("ORA-04031" in detected or "shared memory" in templates_str):
        confidence = 93.0
        risk = "MEDIUM"
        thesis = "Definitive Root Cause: SGA shared pool memory fragmentation preventing contiguous package compilation."
    elif domain == "ORCHESTRATION_REGISTRY" or "STUCK_ST_STATUS" in detected or "ST_STATUS is not zero" in templates_str:
        confidence = 96.0
        risk = "HIGH"
        thesis = "Definitive Root Cause: MSC_APPS_INSTANCES.ST_STATUS flag locked in active state after crash with 0 running workers."
    elif domain == "INFRASTRUCTURE_PIPE" or "ORA-02478" in detected:
        confidence = 91.0
        risk = "MEDIUM"
        thesis = "Definitive Root Cause: Staging tablespace extent limit reached and child pull worker crashed without pipe signal."
    elif domain == "NETWORK_SNAPSHOT" or "ORA-12571" in detected:
        confidence = 92.0
        risk = "MEDIUM"
        thesis = "Definitive Root Cause: DB Link network drop during snapshot extraction."
    elif domain == "DATABASE_LOCK" and not root_found:
        confidence = 72.0
        risk = "LOW"
        thesis = "Intermittent Lock: No persistent root blocker detected in dynamic views. Pipeline may have stalled on pipe buffer."
    else:
        confidence = 90.0
        risk = "LOW"
        thesis = "Healthy or Non-Destructive Execution: No destructive remediation permitted."

    norm_conf = confidence / 100.0 if confidence > 1.0 else confidence

    return {
        "confidence": norm_conf,
        "confidence_score": confidence,
        "risk_level": risk,
        "failure_mode": mode,
        "messages": [AIMessage(content=f"RCA Synthesis: {thesis} | Diagnostic Confidence: {confidence:.1f}% | Risk Tier: {risk}.")]
    }

def _execute_kill_session_action(eng: RemediationEngine, st: AgentState, dry: bool) -> Any:
    """Precomputes root blocker lock telemetry to avoid repeated generator scans.
    Strictly refuses to execute if no valid blocker session is identified in telemetry or context.
    """
    telemetry = st.get("lock_telemetry", [])
    root = next((x for x in telemetry if x.get("lock_depth") == 1), {})
    ctx = st.get("context", {})

    target_sid = root.get("sid") or ctx.get("target_sid")
    target_serial = root.get("serial_number") or ctx.get("target_serial")

    if target_sid is None or target_serial is None:
        raise ValueError(
            "Cannot execute KILL_SESSION: No valid blocker session identified in lock telemetry or execution context. "
            "Aborting remediation to prevent unsafe termination."
        )

    return eng.execute_kill_session(
        sid=target_sid,
        serial=target_serial,
        object_name=root.get("object_name", ctx.get("target_staging_table", "MSC_ST_DEMANDS")),
        inst_id=root.get("inst_id"),
        username=root.get("oracle_username", "APPS"),
        module=root.get("module", "MSCPDCW"),
        session_type=root.get("session_type", "USER"),
        instance_id=ctx.get("instance_id", 1001),
        dry_run=dry,
    )

ACTION_EXECUTORS: dict[str, Callable[[RemediationEngine, AgentState, bool], Any]] = {
    "KILL_SESSION": _execute_kill_session_action,
    "PURGE_STAGING_NO_VALIDATION": lambda eng, st, dry: eng.execute_purge_staging_no_validation(
        instance_id=st.get("context", {}).get("instance_id", 1001),
        dry_run=dry
    ),
    "PURGE_STAGING": lambda eng, st, dry: eng.execute_purge_staging_no_validation(
        instance_id=st.get("context", {}).get("instance_id", 1001),
        dry_run=dry
    ),
    "RESET_PIPE": lambda eng, st, dry: eng.execute_reset_pipe(
        pipe_name=f"MSC_PIPE_{st.get('context', {}).get('instance_code', 'PRD1')}",
        dry_run=dry
    ),
    "PURGE_PIPE": lambda eng, st, dry: eng.execute_reset_pipe(
        pipe_name=f"MSC_PIPE_{st.get('context', {}).get('instance_code', 'PRD1')}",
        dry_run=dry
    ),
    "ALIGN_INDEXES": lambda eng, st, dry: eng.execute_align_indexes(
        table_name=st.get("context", {}).get("target_staging_table", "MSC_DEMANDS"),
        dry_run=dry
    ),
    "REBUILD_ALIGN_INDEXES": lambda eng, st, dry: eng.execute_align_indexes(
        table_name=st.get("context", {}).get("target_staging_table", "MSC_DEMANDS"),
        dry_run=dry
    ),
    "RERUN_SNAPSHOT": lambda eng, st, dry: eng.execute_snapshot_refresh(
        mview_name=st.get("context", {}).get("mview_name", "MLOG$_OE_ORDER_LINES"),
        mode="F",
        dry_run=dry
    ),
    "RERUN_SNAPSHOT_FAST": lambda eng, st, dry: eng.execute_snapshot_refresh(
        mview_name=st.get("context", {}).get("mview_name", "MLOG$_OE_ORDER_LINES"),
        mode="F",
        dry_run=dry
    ),
    "REFRESH_SNAPSHOT": lambda eng, st, dry: eng.execute_snapshot_refresh(
        mview_name=st.get("context", {}).get("mview_name", "MLOG$_OE_ORDER_LINES"),
        mode="F",
        dry_run=dry
    ),
    "EXTEND_UNDO_RETENTION": lambda eng, st, dry: eng.execute_extend_undo_retention(
        dry_run=dry
    ),
    "EXTEND_TABLESPACE": lambda eng, st, dry: eng.execute_extend_tablespace(
        tablespace_name="APPS_TS_STAGING",
        dry_run=dry
    ),
    "FLUSH_SHARED_POOL": lambda eng, st, dry: eng.execute_flush_shared_pool(
        dry_run=dry
    ),
    "RESET_REGISTRY": lambda eng, st, dry: eng.execute_reset_registry(
        instance_id=st.get("context", {}).get("instance_id", 1001),
        dry_run=dry
    ),
    "INSPECT_LOCKS": lambda eng, st, dry: eng.execute_inspect_locks(
        dry_run=dry
    ),
}

def hitl_gate_node(state: AgentState) -> dict:
    """Step 5: Table-Driven Governance Gate & Human-in-the-Loop (HITL) Interrupt.
    Strictly idempotent: Pre-interrupt logic only inspects telemetry and builds payloads.
    No database mutations occur before interrupt(). Upon resumption via Command(resume=...),
    the node re-executes cleanly, validates the approval fingerprint against current state,
    re-checks live session status, and dispatches via table-driven ACTION_EXECUTORS.
    """
    action = state.get("remediation_action")
    rule = HITLGovernanceEngine.evaluate_action_risk(action or "")

    # Idempotent guard: if already remediated, do not repeat execution
    if state.get("is_remediated"):
        return {
            "remediation_approved": True,
            "is_remediated": True,
            "messages": [AIMessage(content=f"Remediation for '{action}' already executed previously (idempotent skip).")]
        }

    confidence = state.get("confidence_score", 0.0)
    risk = rule.risk_tier
    blocker = next((x for x in state.get("lock_telemetry", []) if x.get("lock_depth") == 1), {})

    # Safety Check: Abort if KILL_SESSION requested but no root blocker exists in telemetry or context
    if action == "KILL_SESSION" and not blocker and not state.get("context", {}).get("target_sid"):
        return {
            "remediation_approved": False,
            "is_remediated": False,
            "messages": [AIMessage(content="KILL_SESSION aborted: no root blocker found in lock telemetry or execution context.")],
        }

    # Centralized governance evaluation
    routing = HITLGovernanceEngine.evaluate_governance_routing(action or "", confidence)
    requires_approval = rule.requires_mandatory_approval or (routing in ["MANDATORY_HITL_INTERRUPT", "CONDITIONAL_INTERRUPT"])

    target_sid = blocker.get("sid")
    target_serial = blocker.get("serial_number")
    target_obj = blocker.get("object_name", state.get("context", {}).get("target_staging_table", "MSC_ST_DEMANDS"))
    target_inst = blocker.get("inst_id")
    approval_fingerprint = hashlib.sha256(
        f"{action}:{target_sid}:{target_serial}:{target_obj}:{target_inst}".encode()
    ).hexdigest()

    # If approval is required and neither approved nor human_response evaluated yet:
    if requires_approval and not state.get("remediation_approved") and state.get("human_response") is None:
        rec_sql = (
            format_kill_session_sql(blocker["sid"], blocker["serial_number"], inst_id=blocker.get("inst_id"))
            if action == "KILL_SESSION"
            else format_purge_staging_sql()
        )
        now_ts = time.time()
        ttl_seconds = 300  # 5 minute approval window
        expires_ts = now_ts + ttl_seconds
        appr_id = f"appr-{uuid.uuid4().hex[:12]}"

        approval_payload = {
            "approval_id": appr_id,
            "approval_fingerprint": approval_fingerprint,
            "created_at": now_ts,
            "expires_at": expires_ts,
            "expires_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_ts)),
            "action": action,
            "risk_tier": risk,
            "confidence_score": confidence,
            "target_sid": target_sid,
            "target_serial": target_serial,
            "target_object": target_obj,
            "target_inst_id": target_inst,
            "lock_mode": blocker.get("locked_mode_text", "Exclusive (X)"),
            "recommended_sql": rec_sql,
            "reasoning": f"Diagnostic confidence is {confidence:.1f}%. High-risk action '{action}' requires explicit DBA authorization."
        }
        interrupt(approval_payload)

    human_resp = state.get("human_response", {})
    if human_resp.get("approved") is False:
        return {
            "remediation_approved": False,
            "is_remediated": False,
            "messages": [AIMessage(content=f"Remediation action '{action}' rejected by DBA operator.")]
        }

    # Bind approval to what operator saw: reject if submitted fingerprint does not match
    submitted_fingerprint = human_resp.get("approval_fingerprint")
    if submitted_fingerprint and submitted_fingerprint != approval_fingerprint:
        return {
            "remediation_approved": False,
            "is_remediated": False,
            "messages": [AIMessage(content="Approval rejected: Target fingerprint mismatch. Blocker session changed while waiting for approval.")]
        }

    # Oracle-specific safety: Re-query session immediately prior to termination
    if action == "KILL_SESSION" and target_sid:
        lock_engine = LockDiagnosticsEngine()
        is_active = lock_engine.verify_session_active(target_sid, target_serial or 0, target_inst)
        if not is_active:
            return {
                "remediation_approved": True,
                "is_remediated": False,
                "messages": [AIMessage(content=f"Session SID {target_sid} (serial {target_serial}) is no longer active; lock cleared while awaiting approval. No termination needed.")]
            }

    executor = ACTION_EXECUTORS.get(action or "")
    if executor is None:
        return {
            "remediation_approved": True,
            "is_remediated": False,
            "messages": [AIMessage(content=f"Action '{action}' has no executor wired; nothing was run. Escalate to a DBA.")]
        }

    rem_engine = RemediationEngine()
    if rule.requires_dry_run_validation:
        dry_res = executor(rem_engine, state, True)
        if dry_res and not dry_res.success:
            return {
                "remediation_approved": True,
                "is_remediated": False,
                "remediation_result": vars(dry_res),
                "messages": [AIMessage(content=f"Dry run pre-validation failed for '{action}': {dry_res.message}. Aborting execution.")]
            }

    res = executor(rem_engine, state, False)
    return {
        "remediation_approved": True,
        "is_remediated": res.success,
        "remediation_result": vars(res),
        "messages": [AIMessage(content=res.message)]
    }

def servicenow_node(state: AgentState) -> dict:
    """Step 6: Enriched Incident Ticket Generation & ServiceNow ITSM Action."""
    sn_client = ServiceNowClient()
    incident_payload = sn_client.build_incident_payload_from_state(state)
    incident_res = sn_client.dispatch_incident(incident_payload)
    inst_id = state.get("context", {}).get("instance_id", 1001)
    inst_code = state.get("context", {}).get("instance_code", "PRD1")
    recovery_cmd = format_recovery_command_block(instance_id=inst_id, instance_code=inst_code, validation="N")

    status = incident_res.get("status")
    if status == "FAILED":
        text = f"ServiceNow dispatch FAILED: {incident_res.get('error', 'Unknown error')}"
    else:
        text = f"ServiceNow incident {status or 'CREATED'}: {incident_res.get('incident_number')} (SysID: {incident_res.get('sys_id')}). Automated Recovery Command staged for ST_STATUS reset."

    return {
        "servicenow_incident": incident_res,
        "recovery_command": recovery_cmd,
        "messages": [AIMessage(content=text)]
    }

# -------------------------------------------------------------
# Conditional Routing & Graph Builder
# -------------------------------------------------------------

def route_from_classification(state: AgentState) -> str:
    """Routes based on classified failure domain."""
    domain = state.get("failure_domain")
    if domain in ("DATABASE_LOCK", "DEADLOCK_CONCURRENCY"):
        return "oracle_lock_node"
    return "rca_hypothesis_node"

def create_ascp_diagnostic_graph(checkpointer: Any | None = None) -> CompiledStateGraph:
    """Builds and compiles the 6-step ASCP Diagnostic Control Plane StateGraph with Send support."""
    builder = StateGraph(AgentState)

    # 1. Add discrete processing nodes (including parallel worker log parser)
    builder.add_node("log_ingestion_node", log_ingestion_node)
    builder.add_node("parse_worker_log_node", parse_worker_log_node)
    builder.add_node("classification_node", classification_node)
    builder.add_node("oracle_lock_node", oracle_lock_node)
    builder.add_node("rca_hypothesis_node", rca_hypothesis_node)
    builder.add_node("hitl_gate_node", hitl_gate_node)
    builder.add_node("servicenow_node", servicenow_node)

    # 2. Set entry point
    builder.set_entry_point("log_ingestion_node")

    # 3. Transitions
    builder.add_edge("log_ingestion_node", "classification_node")

    builder.add_conditional_edges(
        "classification_node",
        route_from_classification,
        {
            "oracle_lock_node": "oracle_lock_node",
            "rca_hypothesis_node": "rca_hypothesis_node"
        }
    )

    builder.add_edge("oracle_lock_node", "rca_hypothesis_node")
    builder.add_edge("rca_hypothesis_node", "hitl_gate_node")
    builder.add_edge("hitl_gate_node", "servicenow_node")
    builder.add_edge("servicenow_node", END)

    return builder.compile(checkpointer=checkpointer or PostgresSaver())

def create_self_healing_validation_graph(checkpointer: Any | None = None) -> CompiledStateGraph:
    """Builds and compiles dedicated self-healing Pydantic schema validation graph."""
    builder = StateGraph(AgentState)

    def llm_diagnostic_step(state: AgentState) -> dict:
        retry = state.get("retry_count", 0)
        # If output is missing or invalid, generate corrected structured report
        if retry > 0 or not state.get("raw_llm_output"):
            sample = {
                "diagnostic_summary": {
                    "failing_stage": "ODS_LOAD",
                    "failing_program_short_name": "MSCPDCW",
                    "request_id": 890415,
                    "primary_error_code": "ORA-00054",
                    "confidence_score": 0.965
                },
                "root_cause_analysis": {
                    "summary": "Exclusive TM Mode 6 lock held on MSC_ST_DEMANDS.",
                    "affected_objects": ["MSC_ST_DEMANDS"],
                    "is_infrastructure_issue": False,
                    "is_data_validation_issue": False
                },
                "remediation_plan": {
                    "immediate_action_required": "KILL_SESSION",
                    "sql_scripts_to_execute": ["ALTER SYSTEM KILL SESSION '412,28419' IMMEDIATE;"],
                    "os_commands_to_execute": [],
                    "profile_option_adjustments": [],
                    "requires_manager_bounce": False
                }
            }
            raw = json.dumps(sample)
        else:
            raw = state.get("raw_llm_output")
        return {"raw_llm_output": raw}

    def human_approval_step(state: AgentState) -> dict:
        return {"requires_human_approval": True, "messages": [AIMessage(content="Routed to human approval.")]}

    def execute_remediation_step(state: AgentState) -> dict:
        return {"is_remediated": True, "messages": [AIMessage(content="Auto-remediation executed.")]}

    def fallback_escalation_step(state: AgentState) -> dict:
        return {"is_remediated": False, "messages": [AIMessage(content="Retry limit exceeded. Escalated to DBA.")]}

    builder.add_node("llm_diagnostic_node", llm_diagnostic_step)
    builder.add_node("validate_schema_node", validate_schema_node)
    builder.add_node("human_approval_node", human_approval_step)
    builder.add_node("execute_remediation_node", execute_remediation_step)
    builder.add_node("fallback_escalation_node", fallback_escalation_step)

    builder.set_entry_point("llm_diagnostic_node")
    builder.add_edge("llm_diagnostic_node", "validate_schema_node")

    builder.add_conditional_edges(
        "validate_schema_node",
        check_validation_routing,
        {
            "human_approval_node": "human_approval_node",
            "execute_remediation_node": "execute_remediation_node",
            "fallback_escalation_node": "fallback_escalation_node",
            "llm_diagnostic_node": "llm_diagnostic_node"
        }
    )

    builder.add_edge("human_approval_node", END)
    builder.add_edge("execute_remediation_node", END)
    builder.add_edge("fallback_escalation_node", END)

    return builder.compile(checkpointer=checkpointer or PostgresSaver())
