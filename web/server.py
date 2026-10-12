"""High-performance HTTP server for ASCP Collections Diagnostic Agent Web Dashboard.
Runs zero-dependency with Python standard library.
Provides REST APIs for pipeline telemetry, Drain parsing, lock analysis, LangGraph execution,
HITL gate approval, and static file serving.
"""

import http.server
import socketserver
import json
import os
import sys
import urllib.parse
from typing import Dict, Any

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
from ascp_agent.remediation import RemediationEngine
from ascp_agent.hitl_governance import HITLGovernanceEngine
from ascp_agent.guardrails import EnterpriseGuardrails

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.abspath(os.path.join(WEB_DIR, "public"))

# Application session state
current_scenario_key = "ora_00054_mode6"
active_graph = create_ascp_diagnostic_graph()
last_graph_state: Dict[str, Any] = {}
thread_counter = 1

class ASCPDiagnosticHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def translate_path(self, path):
        """Map URL path directly to PUBLIC_DIR regardless of working directory or Python version."""
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        words = [w for w in path.split('/') if w]
        full_path = PUBLIC_DIR
        for word in words:
            if word in (os.curdir, os.pardir):
                continue
            full_path = os.path.join(full_path, word)
        if os.path.isdir(full_path):
            full_path = os.path.join(full_path, "index.html")
        return full_path

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        global current_scenario_key, last_graph_state
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            scenario_info = SCENARIOS.get(current_scenario_key, SCENARIOS["ora_00054_mode6"])
            monitor = PipelineMonitor(simulated_scenario=scenario_info.get("lock_scenario", "stage2_stalled"))
            registry = monitor.get_instance_registry(instance_id=scenario_info["instance_id"])
            stages = monitor.get_pipeline_stages_telemetry()
            quarantine = monitor.get_staging_quarantine_records()

            self._send_json({
                "scenario": scenario_info,
                "scenario_key": current_scenario_key,
                "registry": vars(registry),
                "stages": stages,
                "quarantine_records": quarantine
            })

        elif path == "/api/scenarios":
            self._send_json({
                "scenarios": [
                    {"key": k, "name": v["name"], "description": v["description"], "stage": v["stage"]}
                    for k, v in SCENARIOS.items()
                ]
            })

        elif path == "/api/locks":
            scenario_info = SCENARIOS.get(current_scenario_key, SCENARIOS["ora_00054_mode6"])
            engine = LockDiagnosticsEngine(simulated_scenario=scenario_info.get("lock_scenario", "ora_00054_mode6"))
            telemetry = engine.execute_hierarchical_lock_query()
            root = engine.isolate_root_blocker(telemetry)
            self._send_json({
                "telemetry": telemetry,
                "root_blocker": root,
                "lock_mode_catalog": {k: {"name": v[0], "desc": v[1]} for k, v in LOCK_MODE_MAPPING.items()}
            })

        elif path == "/api/state":
            self._send_json({"state": last_graph_state})

        else:
            # Direct static file serving from PUBLIC_DIR
            clean_path = path.lstrip('/')
            if not clean_path:
                clean_path = "index.html"
            file_path = os.path.join(PUBLIC_DIR, clean_path)
            if not os.path.exists(file_path):
                # Fallback to web directory
                file_path = os.path.join(os.path.dirname(__file__), clean_path)

            if os.path.exists(file_path) and os.path.isfile(file_path):
                content_type = "text/html; charset=utf-8"
                if file_path.endswith(".css"):
                    content_type = "text/css; charset=utf-8"
                elif file_path.endswith(".js"):
                    content_type = "application/javascript; charset=utf-8"
                elif file_path.endswith(".json"):
                    content_type = "application/json; charset=utf-8"
                elif file_path.endswith(".svg"):
                    content_type = "image/svg+xml"

                with open(file_path, "rb") as f:
                    content = f.read()

                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, f"File not found: {path}")

    def do_POST(self):
        global current_scenario_key, active_graph, last_graph_state, thread_counter
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            req_data = json.loads(body) if body else {}
        except Exception:
            req_data = {}

        if path == "/api/scenario/load":
            key = req_data.get("key", "ora_00054_mode6")
            if key in SCENARIOS:
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
                # Use current scenario log if none provided
                log_text = "\n".join(SCENARIOS[current_scenario_key]["logs"])
            parser = DrainLogParser()
            parsed_results = parser.parse_log_text(log_text)
            self._send_json({"results": parsed_results, "count": len(parsed_results)})

        elif path == "/api/diagnose":
            action = req_data.get("action")  # e.g., "RESUME" or "START"
            thread_id = f"web-thread-{thread_counter}"

            if action == "RESUME":
                approved = req_data.get("approved", True)
                notes = req_data.get("notes", "Approved via Web Dashboard")
                resume_cmd = Command(resume={"approved": approved, "dba_user": "OPERATOR", "notes": notes})
                state = active_graph.invoke(
                    config={"configurable": {"thread_id": thread_id}},
                    resume_command=resume_cmd
                )
            else:
                raw_logs = SCENARIOS[current_scenario_key]["logs"]
                state = active_graph.invoke(
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

            last_graph_state = dict(state)
            last_graph_state["messages"] = serialized_msgs

            self._send_json({
                "state": last_graph_state,
                "interrupted": state.get("interrupted", False),
                "interrupt_payload": state.get("interrupt_payload"),
                "completed": state.get("completed", False)
            })

        elif path == "/api/remediate":
            rem_action = req_data.get("action", "KILL_SESSION")
            engine = RemediationEngine()
            if rem_action == "KILL_SESSION":
                sid = req_data.get("sid", 412)
                serial = req_data.get("serial", 28419)
                obj = req_data.get("object", "MSC_ST_DEMANDS")
                res = engine.execute_kill_session(sid, serial, obj)
            elif rem_action == "PURGE_STAGING":
                inst = req_data.get("instance_id", 1001)
                res = engine.execute_purge_staging(inst)
            elif rem_action == "RESET_PIPE":
                res = engine.execute_reset_pipe()
            else:
                res = engine.execute_align_indexes()

            self._send_json({"result": vars(res)})

        else:
            self._send_json({"error": "Endpoint not found"}, 404)

def run_server(port: int = 8080):
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", port), ASCPDiagnosticHandler) as httpd:
        print(f"[+] ASCP Diagnostic Web Dashboard running on http://localhost:{port}")
        httpd.serve_forever()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
