# Autonomous ASCP Collections Diagnostic Agent

### Oracle E-Business Suite (EBS) & Advanced Supply Chain Planning (ASCP) Control Panel

An autonomous, stateful diagnostic control plane built to triage, diagnose, and remediate Oracle ASCP batch collection pipeline failures across dual-stage ETL architectures. Powered by **LangGraph**, **Drain algorithmic log parsing**, and **Oracle dynamic performance view lock introspection**.

---

## Key Capabilities

1. **Dual-Stage ETL Pipeline Monitoring & Registry Tracking**
   - Monitors execution progression across **Source ADS** &rarr; **Snapshot Logs (`MLOG$_`)** &rarr; **Stage 1 Staging (`MSC_ST_*`)** &rarr; **Stage 2 ODS (`MSC_*`, `plan_id = -1`)** &rarr; **Stage 3 PDS (`plan_id > 0`)**.
   - Tracks `MSC_APPS_INSTANCES.ST_STATUS` (0 = IDLE, 1 = PULL_PROCESSING, 2 = LOAD_PROCESSING, 3 = PURGE_PROCESSING, -1 = ERROR_STALLED).

2. **Real-Time Hierarchical Oracle Lock Engine**
   - Interrogates `V$SESSION`, `V$LOCK`, `V$LOCKED_OBJECT`, `DBA_OBJECTS`, and `V$SQL` using recursive `CONNECT BY PRIOR s.sid = s.blocking_session` queries.
   - Maps enqueue lock modes 0 through 6 (`LOCKED_MODE = 6` Exclusive locks blocking `MSC_ST_*` staging truncations and worker writes).

3. **Drain Fixed-Depth Parse Tree Engine**
   - Rapidly tokenizes high-velocity unstructured concurrent request logs into structured templates and parameter vectors (`<TIMESTAMP>`, `<TARGET_OBJECT>`, `<NUM>`).

4. **LangGraph Autonomous State Machine & HITL Governance**
   - Stateful directed graph (`StateGraph`) with typed `DiagnosticState` and explicit field reducers (`add_messages`, list append).
   - Risk-tiered Human-in-the-Loop (HITL) interrupt gates (`interrupt()`) for high-risk actions (e.g., `ALTER SYSTEM KILL SESSION`).
   - Super-step execution cap (max 10 steps) and hard token spend cap ($5.00 limit).

5. **ITSM ServiceNow REST API Integration**
   - Auto-generates structured incident tickets (`POST /api/now/table/incident`) with detailed `u_diagnostic_payload`.

6. **Interactive Glassmorphic Web Dashboard**
   - Real-time animated pipeline flow, interactive hierarchical lock tree, Drain parser studio, and one-click HITL approval modal.

---

## Directory Structure

```
d:\ag-ai\ascp-diagnostic-agent/
├── README.md
├── requirements.txt
├── ascp_agent/
│   ├── config.py             # Oracle DB, ServiceNow, and Guardrails config
│   ├── state.py              # DiagnosticState, Reducers, Command, interrupt primitives
│   ├── graph.py              # LangGraph StateGraph, nodes, routing, checkpointer
│   ├── drain_parser.py       # Drain log parsing tree algorithm
│   ├── lock_engine.py        # Oracle dynamic views & hierarchical lock query
│   ├── pipeline_monitor.py   # ASCP ETL stages & ST_STATUS registry monitor
│   ├── failure_modes.py      # Diagnostic catalog (ORA-00054, ORA-14098, ORA-02478, ORA-00001, ORA-12571)
│   ├── hitl_governance.py    # Risk-tiered HITL governance matrix
│   ├── remediation.py        # Automated remediation subroutines (KILL_SESSION, PURGE_STAGING, etc.)
│   ├── itsm_service_now.py   # ServiceNow Table REST API dispatcher
│   ├── guardrails.py         # Least-privilege, prompt sanitization, step caps, token tracking
│   ├── simulator.py          # Realistic Oracle EBS scenario presets
│   └── cli.py                # Interactive CLI diagnostic utility
├── tests/
│   ├── test_drain_parser.py
│   ├── test_lock_engine.py
│   ├── test_langgraph_agent.py
│   ├── test_failure_scenarios.py
│   └── run_all_tests.py
├── web/
│   ├── server.py             # HTTP server with REST APIs
│   └── public/
│       ├── index.html        # Executive Dashboard UI
│       ├── app.js            # Frontend state & HITL controller
│       └── style.css         # Modern glassmorphism stylesheet
└── sample_logs/              # Real-world Oracle ASCP log files
```

---

## Diagnostic & Remediation Matrix

| Domain | Oracle Objects / Views | Error Code | Root Cause Mechanism | Remediation Procedure |
|---|---|---|---|---|
| **Lock Contention** | `MSC_ST_%`, `V$LOCKED_OBJECT` | `ORA-00054` | Mode 6 Exclusive lock on staging table | Terminate root blocker session via `ALTER SYSTEM KILL SESSION` (HITL Gate) |
| **Purge Maintenance** | `MSC_ST_%`, `MSC_MAPPING_CLAUSES` | `ORA-00001` | Residual staging rows causing surrogate key collisions | Execute `MSCPDCP` subroutine `PURGE_STAGING_TABLES_SUB` |
| **Partition Swap** | `MSC_% Partitions`, `DBA_IND_COLUMNS` | `ORA-14098` | Structural/index mismatch in partition exchange | Realign index definitions across staging and ODS |
| **Infrastructure/IPC**| `V$DB_PIPES`, `MSCPDPW` | `ORA-02478` | Segment extent limit reached or `DBMS_PIPE` deadlock | Purge pipe buffer `DBMS_PIPE.PURGE` and autoextend tablespace |
| **Source Snapshot** | `MLOG$_%`, `DBMS_SNAPSHOT` | `ORA-12571` | DB link timeout during snapshot refresh | Re-execute `DBMS_SNAPSHOT.REFRESH(..., 'F')` |

---

## Quick Start

### 1. Run Unit & Integration Tests
```bash
python tests/run_all_tests.py
```

### 2. Run the CLI
```bash
# Interrogate database locks (hierarchical tree)
python -m ascp_agent.cli locks --scenario ora_00054_mode6

# Tokenize ASCP concurrent request log with Drain
python -m ascp_agent.cli parse-log --file sample_logs/mscpdpw_worker_ora00054_lock.log

# Run autonomous diagnostic state machine
python -m ascp_agent.cli diagnose --scenario ora_00054_mode6
```

### 3. Launch the Web Dashboard
```bash
python web/server.py 8085
```
Open [http://localhost:8085](http://localhost:8085) in your web browser.
