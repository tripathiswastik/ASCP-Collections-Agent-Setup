"""
Python Version: 3.10+ (Target: Python 3.10, 3.11, 3.12)
Purpose: Multi-threaded HTTP server and REST API backend hosting the ASCP Diagnostic Agent monitoring dashboard.
Runs-in: Standalone daemon process, Docker container, or background service (default port 8085).
"""

import http.server
import socketserver
import json
import os
import sys
import threading
import mimetypes
import urllib.parse
from collections import OrderedDict
from typing import Dict, Any, Tuple, Optional

# Add parent directory to sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ascp_agent.drain_parser import DrainLogParser
from ascp_agent.lock_engine import LockDiagnosticsEngine, LOCK_MODE_MAPPING
from ascp_agent.pipeline_monitor import PipelineMonitor
from ascp_agent.graph import create_ascp_diagnostic_graph
from ascp_agent.state import Command
from ascp_agent.simulator import SCENARIOS
from ascp_agent.itsm_service_now import ServiceNowClient
from ascp_agent.remediation import (
    RemediationEngine,
    validate_oracle_identifier,
    validate_session_numeric
)
from ascp_agent.hitl_governance import HITLGovernanceEngine
from ascp_agent.guardrails import EnterpriseGuardrails

# Canonical single source of truth for dashboard static assets
STATIC_DIR = os.path.dirname(os.path.abspath(__file__))

# Thread-safe application session state
_SERVER_LOCK = threading.RLock()
current_scenario_key = "ora_00054_mode6"
active_graph = create_ascp_diagnostic_graph()
last_graph_state: Dict[str, Any] = {}
thread_counter = 1

# Bounded LRU static file cache to prevent memory leaks
_STATIC_CACHE: "OrderedDict[str, Tuple[bytes, str]]" = OrderedDict()
MAX_STATIC_CACHE_ENTRIES = 100
MAX_STATIC_FILE_SIZE = 5 * 1024 * 1024  # 5 MB limit
MAX_REQUEST_PAYLOAD_SIZE = 5 * 1024 * 1024  # 5 MB request limit

class ThreadedASCPDiagnosticServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Multi-threaded non-blocking HTTP server dispatching requests to concurrent worker threads."""
    allow_reuse_address = True
    daemon_threads = True

class ASCPDiagnosticHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def _get_allowed_origin(self) -> str:
        """Restricts CORS to localhost/127.0.0.1 or configured trusted origins."""
        origin = self.headers.get("Origin", "")
        allowed_origins = [
            "http://localhost", "http://127.0.0.1",
            "https://localhost", "https://127.0.0.1"
        ]
        for allowed in allowed_origins:
            if origin.startswith(allowed):
                return origin
        return "http://127.0.0.1:8080"

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", self._get_allowed_origin())
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-DBA-User, X-API-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", self._get_allowed_origin())
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-DBA-User, X-API-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def translate_path(self, path):
        """Map URL path directly to canonical STATIC_DIR with path traversal protection."""
        path = path.split('?', 1)[0].split('#', 1)[0]
        words = [w for w in path.split('/') if w]
        full_path = STATIC_DIR
        for word in words:
            if word in (os.curdir, os.pardir):
                continue
            full_path = os.path.join(full_path, word)
        if os.path.isdir(full_path):
            full_path = os.path.join(full_path, "index.html")

        # Path traversal guard: ensure target is strictly inside STATIC_DIR
        real_target = os.path.realpath(full_path)
        real_static = os.path.realpath(STATIC_DIR)
        if not real_target.startswith(real_static):
            return os.path.join(STATIC_DIR, "index.html")
        return real_target

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            with _SERVER_LOCK:
                scen_key = current_scenario_key
            scenario_info = SCENARIOS.get(scen_key, SCENARIOS["ora_00054_mode6"])
            monitor = PipelineMonitor(simulated_scenario=scenario_info.get("lock_scenario", "stage2_stalled"))
            registry = monitor.get_instance_registry(instance_id=scenario_info["instance_id"])
            stages = monitor.get_pipeline_stages_telemetry()
            quarantine = monitor.get_staging_quarantine_records()

            self._send_json({
                "scenario": scenario_info,
                "scenario_key": scen_key,
                "registry": vars(registry),
                "stages": stages,
                "quarantine_records": quarantine,
                "is_simulation": True
            })

        elif path == "/api/scenarios":
            self._send_json({
                "scenarios": [
                    {"key": k, "name": v["name"], "description": v["description"], "stage": v["stage"]}
                    for k, v in SCENARIOS.items()
                ]
            })

        elif path == "/api/locks":
            with _SERVER_LOCK:
                scen_key = current_scenario_key
            scenario_info = SCENARIOS.get(scen_key, SCENARIOS["ora_00054_mode6"])
            engine = LockDiagnosticsEngine(simulated_scenario=scenario_info.get("lock_scenario", "ora_00054_mode6"))
            telemetry = engine.execute_hierarchical_lock_query()
            root = engine.isolate_root_blocker(telemetry)
            self._send_json({
                "telemetry": telemetry,
                "root_blocker": root,
                "lock_mode_catalog": {k: {"name": v[0], "desc": v[1]} for k, v in LOCK_MODE_MAPPING.items()}
            })

        elif path == "/api/state":
            with _SERVER_LOCK:
                snapshot = dict(last_graph_state)
            self._send_json({"state": snapshot})

        else:
            # Direct static file serving from single canonical directory with bounded LRU memory caching
            clean_path = path.lstrip('/')
            if not clean_path:
                clean_path = "index.html"

            with _SERVER_LOCK:
                if clean_path in _STATIC_CACHE:
                    _STATIC_CACHE.move_to_end(clean_path)
                    content, content_type = _STATIC_CACHE[clean_path]
                else:
                    file_path = os.path.join(STATIC_DIR, clean_path)
                    real_target = os.path.realpath(file_path)
                    real_static = os.path.realpath(STATIC_DIR)

                    if os.path.exists(real_target) and os.path.isfile(real_target) and real_target.startswith(real_static):
                        guessed_type, _ = mimetypes.guess_type(clean_path)
                        content_type = guessed_type or "text/html; charset=utf-8"
                        file_size = os.path.getsize(real_target)
                        with open(real_target, "rb") as f:
                            content = f.read()

                        if file_size <= MAX_STATIC_FILE_SIZE:
                            if len(_STATIC_CACHE) >= MAX_STATIC_CACHE_ENTRIES:
                                _STATIC_CACHE.popitem(last=False)
                            _STATIC_CACHE[clean_path] = (content, content_type)
                    else:
                        self.send_error(404, f"File not found: {path}")
                        return

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("Access-Control-Allow-Origin", self._get_allowed_origin())
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.end_headers()
            self.wfile.write(content)

    def do_POST(self):
        global current_scenario_key, active_graph, last_graph_state, thread_counter
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))

        if length > MAX_REQUEST_PAYLOAD_SIZE:
            self._send_json({"error": "Payload Too Large: exceeded 5MB request limit."}, 413)
            return

        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            req_data = json.loads(body) if body else {}
        except Exception:
            self._send_json({"error": "Malformed JSON in request body."}, 400)
            return

        if path == "/api/scenario/load":
            key = req_data.get("key", "ora_00054_mode6")
            if key in SCENARIOS:
                with _SERVER_LOCK:
                    current_scenario_key = key
                    thread_counter += 1
                    active_graph = create_ascp_diagnostic_graph()
                    last_graph_state = {}
                self._send_json({"success": True, "loaded_scenario": SCENARIOS[key]})
            else:
                self._send_json({"error": "Unknown scenario"}, 400)

        elif path == "/api/parse-log":
            log_text = req_data.get("log_text", "")
            if not log_text:
                with _SERVER_LOCK:
                    scen_key = current_scenario_key
                log_text = "\n".join(SCENARIOS[scen_key]["logs"])
            max_lines = req_data.get("max_lines", 500)
            if not isinstance(max_lines, int) or max_lines < 1:
                max_lines = 500
            max_lines = min(max_lines, 2000)  # Bound line parsing limit

            parser = DrainLogParser()
            parsed_results = parser.parse_log_text(log_text, max_lines=max_lines)
            self._send_json({"results": parsed_results, "count": len(parsed_results)})

        elif path == "/api/diagnose":
            action = req_data.get("action")  # e.g., "RESUME" or "START"
            with _SERVER_LOCK:
                curr_graph = active_graph
                thread_id = f"web-thread-{thread_counter}"
                scen_key = current_scenario_key
                is_currently_interrupted = bool(last_graph_state.get("interrupted"))

            if action == "RESUME":
                # Strict Safety Check 1: Explicit boolean approval is mandatory. Never treat omitted decision as consent.
                if "approved" not in req_data or not isinstance(req_data["approved"], bool):
                    self._send_json({
                        "error": "Explicit boolean 'approved' field (true/false) is mandatory for HITL decision. Omitted decisions are rejected."
                    }, 400)
                    return
                approved = req_data["approved"]

                # Strict Safety Check 2: Reject resumption if state machine is not currently awaiting approval.
                if not is_currently_interrupted:
                    self._send_json({
                        "error": "No pending approval: LangGraph state machine is not currently paused at a HITL gate."
                    }, 409)
                    return

                # Strict Safety Check 3: Authenticate / require operator identity.
                dba_user = req_data.get("dba_user") or self.headers.get("X-DBA-User")
                if not dba_user or not isinstance(dba_user, str) or not dba_user.strip():
                    self._send_json({
                        "error": "Authenticated operator identity ('dba_user' or 'X-DBA-User' header) is required for HITL decisions."
                    }, 401)
                    return
                dba_user = dba_user.strip()

                # Strict Safety Check 4: Bind approval to pending target action to prevent stale or hijacked execution.
                interrupt_payload = last_graph_state.get("interrupt_payload") or {}
                expected_action = interrupt_payload.get("action")
                target_action = req_data.get("target_action")
                if target_action and expected_action and target_action != expected_action:
                    self._send_json({
                        "error": f"Stale approval request: expected action '{expected_action}', received '{target_action}'."
                    }, 409)
                    return

                notes = req_data.get("notes", f"Decision rendered by {dba_user}")
                resume_cmd = Command(resume={"approved": approved, "dba_user": dba_user, "notes": notes})
                state = curr_graph.invoke(
                    config={"configurable": {"thread_id": thread_id}},
                    resume_command=resume_cmd
                )
            else:
                raw_logs = SCENARIOS[scen_key]["logs"]
                state = curr_graph.invoke(
                    initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": raw_logs},
                    config={"configurable": {"thread_id": thread_id}}
                )

            # Convert AIMessage/HumanMessage objects to serializable dicts
            serialized_msgs = []
            for msg in state.get("messages", []):
                serialized_msgs.append({
                    "role": getattr(msg, "role", "agent"),
                    "content": getattr(msg, "content", str(msg))
                })

            with _SERVER_LOCK:
                last_graph_state = dict(state)
                last_graph_state["messages"] = serialized_msgs
                resp_state = dict(last_graph_state)

            self._send_json({
                "state": resp_state,
                "interrupted": state.get("interrupted", False),
                "interrupt_payload": state.get("interrupt_payload"),
                "completed": state.get("completed", False)
            })

        elif path == "/api/remediate":
            rem_action = req_data.get("action", "KILL_SESSION")
            dry_run = bool(req_data.get("dry_run", False))
            engine = RemediationEngine()

            try:
                if rem_action == "KILL_SESSION":
                    sid = validate_session_numeric(req_data.get("sid", 412), "sid")
                    serial = validate_session_numeric(req_data.get("serial", 28419), "serial")
                    obj = validate_oracle_identifier(req_data.get("object", "MSC_ST_DEMANDS"), "object")
                    res = engine.execute_kill_session(sid, serial, obj, dry_run=dry_run)
                elif rem_action == "PURGE_STAGING":
                    inst = validate_session_numeric(req_data.get("instance_id", 1001), "instance_id")
                    res = engine.execute_purge_staging(inst, dry_run=dry_run)
                elif rem_action == "RESET_PIPE":
                    pipe_name = validate_oracle_identifier(req_data.get("pipe_name", "MSC_PIPE_1001"), "pipe_name")
                    res = engine.execute_reset_pipe(pipe_name, dry_run=dry_run)
                else:
                    tbl = validate_oracle_identifier(req_data.get("table_name", "MSC_DEMANDS"), "table_name")
                    res = engine.execute_align_indexes(tbl, dry_run=dry_run)

                self._send_json({"result": vars(res)})
            except ValueError as ve:
                self._send_json({"error": str(ve)}, 400)

        else:
            self._send_json({"error": "Endpoint not found"}, 404)

def run_server(port: int = 8080):
    host = os.getenv("SERVER_HOST", "127.0.0.1")  # Binds strictly to localhost by default
    with ThreadedASCPDiagnosticServer((host, port), ASCPDiagnosticHandler) as httpd:
        print(f"[+] Multi-Threaded ASCP Diagnostic Dashboard running on http://{host}:{port}")
        httpd.serve_forever()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
