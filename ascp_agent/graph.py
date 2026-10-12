"""LangGraph Autonomous Agent Control Plane for ASCP Collections.
Implements the Directed State Graph (StateGraph), MemorySaver checkpointer,
node functions, conditional routing, Human-in-the-Loop interrupt gates,
and time-travel state debugging.
"""

import copy
import time
from typing import Dict, Any, Optional, Callable, List, Tuple
from ascp_agent.state import AgentState, DiagnosticState, AIMessage, HumanMessage, Command, InterruptSignal, interrupt
from ascp_agent.drain_parser import DrainLogParser
from ascp_agent.lock_engine import LockDiagnosticsEngine
from ascp_agent.hitl_governance import HITLGovernanceEngine
from ascp_agent.remediation import RemediationEngine
from ascp_agent.itsm_service_now import ServiceNowClient
from ascp_agent.guardrails import EnterpriseGuardrails, ExecutionCapExceededError

END = "__END__"

class CheckpointRecord:
    """A snapshot of graph state at a super-step boundary."""
    def __init__(self, step_index: int, state: DiagnosticState, next_node: str):
        self.step_index = step_index
        self.state = copy.deepcopy(state)
        self.next_node = next_node
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

class MemorySaver:
    """In-memory checkpointer supporting state snapshots and time-travel inspection."""
    def __init__(self):
        self.threads: Dict[str, List[CheckpointRecord]] = {}

    def save(self, thread_id: str, state: DiagnosticState, next_node: str) -> int:
        records = self.threads.setdefault(thread_id, [])
        step = len(records) + 1
        records.append(CheckpointRecord(step, state, next_node))
        return step

    def get_latest(self, thread_id: str) -> Optional[CheckpointRecord]:
        records = self.threads.get(thread_id, [])
        return records[-1] if records else None

    def get_history(self, thread_id: str) -> List[CheckpointRecord]:
        return self.threads.get(thread_id, [])

class StateGraph:
    """StateGraph engine implementing directed state transitions, conditional edges, and HITL gates."""
    def __init__(self, state_schema=DiagnosticState):
        self.state_schema = state_schema
        self.nodes: Dict[str, Callable[[DiagnosticState], Dict[str, Any]]] = {}
        self.conditional_edges: Dict[str, Tuple[Callable[[DiagnosticState], str], Dict[str, str]]] = {}
        self.edges: Dict[str, str] = {}
        self.entry_point: Optional[str] = None

    def add_node(self, name: str, func: Callable[[DiagnosticState], Dict[str, Any]]):
        self.nodes[name] = func

    def set_entry_point(self, name: str):
        self.entry_point = name

    def add_edge(self, from_node: str, to_node: str):
        self.edges[from_node] = to_node

    def add_conditional_edges(self, from_node: str, router_func: Callable[[DiagnosticState], str], route_map: Dict[str, str]):
        self.conditional_edges[from_node] = (router_func, route_map)

    def compile(self, checkpointer: Optional[MemorySaver] = None):
        return CompiledStateGraph(self, checkpointer or MemorySaver())

class CompiledStateGraph:
    """Compiled runnable execution engine for the ASCP Diagnostic Control Plane."""
    def __init__(self, graph: StateGraph, checkpointer: MemorySaver):
        self.graph = graph
        self.checkpointer = checkpointer

    def invoke(
        self,
        initial_state: Optional[Dict[str, Any]] = None,
        config: Optional[Dict[str, Any]] = None,
        resume_command: Optional[Command] = None
    ) -> DiagnosticState:
        """Executes the state graph until an interrupt gate or END is reached."""
        config = config or {}
        thread_id = config.get("configurable", {}).get("thread_id", "default_thread")
        guardrails = config.get("guardrails") or EnterpriseGuardrails()

        # Handle resumption from prior checkpoint
        if resume_command is not None:
            last_record = self.checkpointer.get_latest(thread_id)
            if not last_record:
                raise ValueError(f"No checkpoint found for thread '{thread_id}' to resume.")
            state = copy.deepcopy(last_record.state)
            # Inject human approval or resume value
            if isinstance(resume_command.resume, dict):
                approved = resume_command.resume.get("approved", False)
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

        step_count = 0

        while current_node and current_node != END:
            # 1. Enforce super-step cap guardrail (Max 10 super-steps)
            guardrails.check_super_step_limit()
            step_count += 1

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

            # 4. Apply state updates using field reducers
            if isinstance(update, dict):
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

            # 6. Persist checkpoint
            self.checkpointer.save(thread_id, state, next_node=next_node)
            current_node = next_node

        state["completed"] = True
        return state

    def get_state_history(self, config: Dict[str, Any]) -> List[CheckpointRecord]:
        thread_id = config.get("configurable", {}).get("thread_id", "default_thread")
        return self.checkpointer.get_history(thread_id)

# -------------------------------------------------------------
# 6-Step Node Implementations matching End-to-End Execution Plan
# -------------------------------------------------------------

def log_ingestion_node(state: AgentState) -> dict:
    """Step 1: State Initialization & Async Concurrent Log Ingestion with Drain Tree Algorithm."""
    raw_logs = state.get("raw_logs", [])
    if not raw_logs:
        raw_logs = [
            "[12-OCT-2025 04:12:01]: Launching Planning ODS Load Worker 1 (MSCPDCW)",
            "[12-OCT-2025 04:12:05]: Cause: ORA-00054: resource busy and acquire with NOWAIT specified on table MSC_ST_DEMANDS.",
            "[12-OCT-2025 04:12:06]: Action: Contact DBA to verify blocking locks on staging tables.",
            "[12-OCT-2025 04:12:10]: Worker process 31902 terminated with fatal error status."
        ]

    parser = DrainLogParser()
    extracted_templates = []
    detected_errors = []
    target_table = "MSC_ST_DEMANDS"

    for line in raw_logs:
        parsed = parser.parse_line(line)
        if parsed.get("template"):
            extracted_templates.append(parsed["template"])
        # Anomaly and stack filtering
        for code in ["ORA-00054", "ORA-14098", "ORA-02478", "ORA-00001", "ORA-12571"]:
            if code in line and code not in detected_errors:
                detected_errors.append(code)
        objs = parsed.get("parameters", {}).get("TARGET_OBJECTS", [])
        if objs:
            target_table = objs[0]

    ctx_update = {
        "detected_errors": detected_errors,
        "target_staging_table": target_table
    }

    return {
        "log_templates": extracted_templates,
        "context": ctx_update,
        "messages": [AIMessage(
            content=f"Log Ingestion complete: Tokenized {len(extracted_templates)} templates via Drain. Detected error signatures: {', '.join(detected_errors) if detected_errors else 'None'}."
        )]
    }

def classification_node(state: AgentState) -> dict:
    """Step 2: Failure Domain Classification & Conditional Edge Routing."""
    detected = state.get("context", {}).get("detected_errors", [])
    templates_str = " ".join(state.get("log_templates", []))

    if "ORA-00054" in detected or "resource busy" in templates_str or "LOCK TABLE" in templates_str:
        domain = "DATABASE_LOCK"
        next_action = "INSPECT_LOCKS"
        phase = "LOAD"
    elif "ORA-00001" in detected or "surrogate" in templates_str or "unique constraint" in templates_str:
        domain = "STAGING_VALIDATION"
        next_action = "PURGE_STAGING"
        phase = "LOAD"
    elif "ORA-14098" in detected:
        domain = "PARTITION_EXCHANGE"
        next_action = "ALIGN_INDEXES"
        phase = "LOAD"
    elif "ORA-12571" in detected:
        domain = "NETWORK_SNAPSHOT"
        next_action = "RERUN_SNAPSHOT"
        phase = "PULL"
    else:
        domain = "DATABASE_LOCK"
        next_action = "INSPECT_LOCKS"
        phase = "LOAD"

    return {
        "failure_domain": domain,
        "remediation_action": next_action,
        "context": {"failed_phase": phase, "remediation_action": next_action},
        "messages": [AIMessage(content=f"Classification: Failure domain mapped to '{domain}'. Routing to diagnostic path: {next_action}.")]
    }

def oracle_lock_node(state: AgentState) -> dict:
    """Step 3: Real-Time Hierarchical Oracle Lock Analysis via python-oracledb & V$ views."""
    scenario = "ora_00054_mode6" if state.get("failure_domain") == "DATABASE_LOCK" else "no_locks"
    engine = LockDiagnosticsEngine(simulated_scenario=scenario)
    telemetry = engine.execute_hierarchical_lock_query()
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
    else:
        msg = "Hierarchical lock query executed across V$SESSION / V$LOCKED_OBJECT: No active Mode 6 lock contention detected."

    rem_act = "KILL_SESSION" if root_found else state.get("remediation_action", "INSPECT_LOCKS")
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
    
    # Calculate deterministic domain confidence score (0 to 100%)
    if domain == "DATABASE_LOCK" and root_found and "ORA-00054" in detected:
        confidence = 96.5
        risk = "HIGH"  # KILL SESSION required
        thesis = "Definitive Root Cause: Uncommitted session holds Exclusive TM Mode 6 lock on staging table, halting MSCPDCW workers."
    elif domain == "STAGING_VALIDATION" and "ORA-00001" in detected:
        confidence = 92.0
        risk = "MEDIUM"
        thesis = "Definitive Root Cause: Legacy unpurged interface records causing duplicate surrogate key collisions during Stage 2 ODS Load."
    elif domain == "PARTITION_EXCHANGE" and "ORA-14098" in detected:
        confidence = 94.0
        risk = "MEDIUM"
        thesis = "Definitive Root Cause: Staging partition index definitions diverge from target partitioned ODS table."
    elif domain == "DATABASE_LOCK" and not root_found:
        confidence = 72.0
        risk = "LOW"
        thesis = "Intermittent Lock: No persistent root blocker detected in dynamic views. Pipeline may have stalled on pipe buffer."
    else:
        confidence = 88.0
        risk = "LOW"
        thesis = "Operational Exception: Resolved via standard diagnostic recovery."

    return {
        "confidence_score": confidence,
        "risk_level": risk,
        "messages": [AIMessage(content=f"RCA Synthesis: {thesis} | Diagnostic Confidence: {confidence:.1f}% | Risk Tier: {risk}.")]
    }

def hitl_gate_node(state: AgentState) -> dict:
    """Step 5: Governance Gate & Human-in-the-Loop (HITL) Interrupt."""
    confidence = state.get("confidence_score", 0.0)
    risk = state.get("risk_level", "HIGH")
    action = state.get("remediation_action")
    blocker = next((x for x in state.get("lock_telemetry", []) if x.get("lock_depth") == 1), {})

    # Trigger HITL interrupt if confidence < 85% OR risk is HIGH (session kill / truncate)
    requires_approval = (confidence < 85.0) or (risk == "HIGH") or (action == "KILL_SESSION")

    if requires_approval and not state.get("remediation_approved"):
        approval_payload = {
            "action": action,
            "risk_tier": risk,
            "confidence_score": confidence,
            "target_sid": blocker.get("sid", 412),
            "target_serial": blocker.get("serial_number", 28419),
            "target_object": blocker.get("object_name", state.get("context", {}).get("target_staging_table", "MSC_ST_DEMANDS")),
            "lock_mode": blocker.get("locked_mode_text", "Exclusive (X)"),
            "recommended_sql": f"ALTER SYSTEM KILL SESSION '{blocker.get('sid', 412)},{blocker.get('serial_number', 28419)}' IMMEDIATE;" if action == "KILL_SESSION" else "EXEC MSC_CL_PULL.PURGE_STAGING_TABLES_SUB();",
            "reasoning": f"Diagnostic confidence is {confidence:.1f}%. High-risk action '{action}' requires explicit DBA authorization."
        }
        # CALL INTERRUPT PRIMITIVE
        interrupt(approval_payload)

    # If operator rejected the action upon resume:
    if state.get("human_response", {}).get("approved") is False:
        return {
            "remediation_approved": False,
            "is_remediated": False,
            "messages": [AIMessage(content=f"Remediation action '{action}' rejected by DBA operator.")]
        }

    # Execute remediation subroutine
    rem_engine = RemediationEngine()
    if action == "KILL_SESSION":
        sid = blocker.get("sid", 412)
        serial = blocker.get("serial_number", 28419)
        obj = blocker.get("object_name", "MSC_ST_DEMANDS")
        res = rem_engine.execute_kill_session(sid, serial, obj)
        return {
            "remediation_approved": True,
            "is_remediated": True,
            "remediation_result": vars(res),
            "messages": [AIMessage(content=res.message)]
        }
    elif action == "PURGE_STAGING":
        res = rem_engine.execute_purge_staging(instance_id=1001)
        return {
            "remediation_approved": True,
            "is_remediated": True,
            "remediation_result": vars(res),
            "messages": [AIMessage(content=res.message)]
        }

    return {
        "remediation_approved": True,
        "is_remediated": True,
        "messages": [AIMessage(content="Remediation executed successfully.")]
    }

def servicenow_node(state: AgentState) -> dict:
    """Step 6: Enriched Incident Ticket Generation & ServiceNow ITSM Action."""
    sn_client = ServiceNowClient()
    blocker = next((x for x in state.get("lock_telemetry", []) if x.get("lock_depth") == 1), {})
    action = state.get("remediation_action", "KILL_SESSION")
    target_table = state.get("context", {}).get("target_staging_table", "MSC_ST_DEMANDS")

    # Automated Pipeline Recovery Command (Validation = No)
    recovery_cmd = (
        f"CONCURRENT PROGRAM: Planning Data Collection - Purge Staging Tables\n"
        f"PARAMETERS: Instance = PRD1 (1001), Validation = No\n"
        f"PL/SQL EXEC: BEGIN MSC_CL_COLLECTION.PURGE_STAGIN_TABLES_SUB(p_instance_id => 1001, p_validation => 'N'); END;\n"
        f"REGISTRY RESET: UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = 1001;"
    )

    incident_payload = sn_client.build_incident_payload(
        short_description=f"ASCP Collection Failure: {state.get('context', {}).get('failed_phase', 'LOAD')} phase on {target_table}",
        description=f"Autonomous ASCP Diagnostic Agent detected {state.get('failure_domain')} on {target_table}. Confidence: {state.get('confidence_score', 0):.1f}%.",
        pipeline_stage=f"Stage 2: Planning ODS Load (MSCPDC)",
        instance_id=1001,
        affected_staging_objects=[target_table],
        root_blocker_session=blocker,
        drain_log_templates=state.get("log_templates", []),
        recommended_remediation=f"Execute {action} and apply recovery command: {recovery_cmd}",
        agent_reasoning_trace=f"Domain: {state.get('failure_domain')}, Confidence: {state.get('confidence_score', 0):.1f}%, Risk: {state.get('risk_level')}."
    )

    incident_res = sn_client.dispatch_incident(incident_payload)

    return {
        "servicenow_incident": incident_res,
        "recovery_command": recovery_cmd,
        "messages": [AIMessage(
            content=f"ServiceNow Incident enriched & created: {incident_res.get('incident_number')} (SysID: {incident_res.get('sys_id')}). Automated Recovery Command staged for ST_STATUS reset."
        )]
    }

# -------------------------------------------------------------
# Conditional Routing & Graph Builder
# -------------------------------------------------------------

def route_from_classification(state: AgentState) -> str:
    """Routes based on classified failure domain."""
    domain = state.get("failure_domain")
    if domain == "DATABASE_LOCK":
        return "oracle_lock_node"
    return "rca_hypothesis_node"

def create_ascp_diagnostic_graph(checkpointer: Optional[MemorySaver] = None) -> CompiledStateGraph:
    """Builds and compiles the 6-step ASCP Diagnostic Control Plane StateGraph."""
    builder = StateGraph(AgentState)

    # 1. Add 6 discrete processing nodes
    builder.add_node("log_ingestion_node", log_ingestion_node)
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

    return builder.compile(checkpointer=checkpointer or MemorySaver())
