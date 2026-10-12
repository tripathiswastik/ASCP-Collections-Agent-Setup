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
import hmac
from typing import Dict, Any, Optional

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

# Canonical single source of truth for dashboard static assets
PUBLIC_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = PUBLIC_DIR

# JSON map of token -> operator name, e.g. {"s3cr3t-token": "alice"}
_RAW_TOKENS = os.environ.get("ASCP_OPERATOR_TOKENS")
if _RAW_TOKENS:
    OPERATOR_TOKENS: Dict[str, str] = json.loads(_RAW_TOKENS)
else:
    OPERATOR_TOKENS: Dict[str, str] = {"dev-token": "operator", "admin-token": "lead_dba"}

# Concurrency & request safety limits
MAX_BODY_BYTES = 64 * 1024
_INVOKE_LOCK = threading.Lock()

# Thread-safe application session state
_SERVER_LOCK = threading.RLock()
current_scenario_key = "ora_00054_mode6"
active_graph = create_ascp_diagnostic_graph()
last_graph_state: Dict[str, Any] = {}
thread_counter = 1


def resolve_static_path(url_path: str) -> Optional[str]:
    """Return an absolute file path inside PUBLIC_DIR, or None if not allowed."""
    relative = urllib.parse.unquote(url_path).lstrip("/") or "index.html"
    public_root = os.path.realpath(PUBLIC_DIR)
    candidate = os.path.realpath(os.path.join(public_root, relative))
    try:
        inside = os.path.commonpath([candidate, public_root]) == public_root
    except ValueError:  # different drives on Windows
        return None
    if not inside or not os.path.isfile(candidate):
        return None
    return candidate


class ThreadedASCPDiagnosticServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Multi-threaded non-blocking HTTP server dispatching requests to concurrent worker threads."""
    allow_reuse_address = True
    daemon_threads = True


class ASCPDiagnosticHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def _authenticate(self) -> Optional[str]:
        """Return the operator name for a valid X-API-Token header, else None."""
        supplied = self.headers.get("X-API-Token", "").encode("utf-8")
        if not supplied:
            return None
        for token, username in OPERATOR_TOKENS.items():
            if hmac.compare_digest(supplied, token.encode("utf-8")):
                return username
        return None

    def _read_json_body(self) -> Optional[Dict[str, Any]]:
        """Return the parsed JSON object, or None if the body is invalid or too large."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            return None
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/"):
            operator = self._authenticate()
            if operator is None:
                self._send_json({"error": "Unauthorized"}, 401)
                return

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
            file_path = resolve_static_path(path)
            if file_path is None:
                self.send_error(404, "File not found")
                return

            guessed_type, _ = mimetypes.guess_type(file_path)
            content_type = guessed_type or "text/html; charset=utf-8"
            with open(file_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.end_headers()
            self.wfile.write(content)

    def do_POST(self):
        global current_scenario_key, active_graph, last_graph_state, thread_counter
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        operator = self._authenticate()
        if operator is None:
            self._send_json({"error": "Unauthorized"}, 401)
            return

        req_data = self._read_json_body()
        if req_data is None:
            self._send_json({"error": "Invalid request body"}, 400)
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
            max_lines = min(max_lines, 2000)

            parser = DrainLogParser()
            parsed_results = parser.parse_log_text(log_text, max_lines=max_lines)
            self._send_json({"results": parsed_results, "count": len(parsed_results)})

        elif path == "/api/diagnose":
            action = req_data.get("action")  # e.g., "RESUME" or "START"
            with _SERVER_LOCK:
                curr_graph = active_graph
                thread_id = f"web-thread-{thread_counter}"
                scen_key = current_scenario_key

            if action == "RESUME":
                approved = req_data.get("approved")
                if not isinstance(approved, bool):
                    self._send_json({"error": "'approved' must be true or false"}, 400)
                    return

                notes = str(req_data.get("notes", f"Decision rendered by {operator}"))[:500]
                resume_cmd = Command(resume={"approved": approved, "dba_user": operator, "notes": notes})
                with _INVOKE_LOCK:
                    state = curr_graph.invoke(
                        config={"configurable": {"thread_id": thread_id}},
                        resume_command=resume_cmd
                    )
            else:
                raw_logs = SCENARIOS[scen_key]["logs"]
                with _INVOKE_LOCK:
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

        else:
            # /api/remediate removed: remediation runs only through the graph's HITL gate.
            self._send_json({"error": "Endpoint not found"}, 404)


def run_server(port: int = 8080):
    with ThreadedASCPDiagnosticServer(("127.0.0.1", port), ASCPDiagnosticHandler) as httpd:
        print(f"[+] Multi-Threaded ASCP Diagnostic Dashboard running on http://127.0.0.1:{port}")
        httpd.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
