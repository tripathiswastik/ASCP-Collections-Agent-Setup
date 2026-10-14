"""
Python Version: 3.10+ (Target: Python 3.10, 3.11, 3.12)
Purpose: Multi-threaded HTTP server and REST API backend hosting the ASCP Diagnostic Agent monitoring dashboard.
Runs-in: Standalone daemon process, Docker container, or background service (default port 8085).
"""

from __future__ import annotations

import hmac
import http.server
import json
import logging
import mimetypes
import os
import secrets as std_secrets
import socketserver
import sys
import threading
import time
import urllib.parse
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# Add parent directory to sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ascp_agent.drain_parser import DrainLogParser
from ascp_agent.graph import create_ascp_diagnostic_graph
from ascp_agent.lock_engine import LOCK_MODE_MAPPING, LockDiagnosticsEngine
from ascp_agent.metrics import GLOBAL_METRICS
from ascp_agent.pipeline_monitor import PipelineMonitor
from ascp_agent.secret_store import GLOBAL_SECRET_MANAGER
from ascp_agent.simulator import SCENARIOS
from ascp_agent.state import Command

# Canonical single source of truth for dashboard static assets
PUBLIC_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = PUBLIC_DIR

# Initial JSON map of token -> operator name, e.g. {"s3cr3t-token": "alice"}
OPERATOR_TOKENS: dict[str, Any] = json.loads(os.environ.get("ASCP_OPERATOR_TOKENS", "{}"))

# Concurrency & request safety limits
MAX_BODY_BYTES = 64 * 1024
_INVOKE_LOCK = threading.Lock()

# Thread-safe multi-session state & anti-replay approval tracking
_SERVER_LOCK = threading.RLock()
current_scenario_key = "ora_00054_mode6"

# Dict of used approval IDs -> expiry unix timestamp to prevent replay attacks and bound memory
_USED_APPROVAL_IDS: dict[str, float] = {}  # approval_id -> expiry (unix)


def _remember_approval(appr_id: str, expires_at: float) -> None:
    now = time.time()
    with _SERVER_LOCK:
        for old_id in [k for k, exp in _USED_APPROVAL_IDS.items() if exp < now]:
            del _USED_APPROVAL_IDS[old_id]
        _USED_APPROVAL_IDS[appr_id] = expires_at

# Multi-session registry supporting concurrent / simultaneous diagnostic sessions
MAX_SESSIONS = 50
SESSION_TTL_SECONDS = 3600  # 1 hour
_SESSIONS: dict[str, dict[str, Any]] = {}
_ACTIVE_SESSION_ID: str = "default"
thread_counter = 1
_DEFAULT_SESSION_INITIALIZED = False


def _init_default_session() -> None:
    """Lazily initialize baseline default session on first server access or startup."""
    global _DEFAULT_SESSION_INITIALIZED
    if _DEFAULT_SESSION_INITIALIZED and _ACTIVE_SESSION_ID in _SESSIONS:
        return
    with _SERVER_LOCK:
        if _DEFAULT_SESSION_INITIALIZED and _ACTIVE_SESSION_ID in _SESSIONS:
            return
        _SESSIONS[_ACTIVE_SESSION_ID] = {
            "graph": create_ascp_diagnostic_graph(),
            "thread_id": "web-thread-1",
            "scenario_key": current_scenario_key,
            "session_id": _ACTIVE_SESSION_ID,
            "pending_approval": None,
            "created_at": time.time(),
            "last_state": {}
        }
        _DEFAULT_SESSION_INITIALIZED = True


def _prune_expired_sessions() -> None:
    """Prune inactive sessions to prevent unbounded memory growth."""
    with _SERVER_LOCK:
        now = time.time()
        expired = [
            sid for sid, sinfo in _SESSIONS.items()
            if sid != "default" and (now - sinfo.get("created_at", now) > SESSION_TTL_SECONDS)
        ]
        for sid in expired:
            _SESSIONS.pop(sid, None)
        if len(_SESSIONS) > MAX_SESSIONS:
            sorted_sids = sorted(
                (sid for sid in _SESSIONS if sid != "default"),
                key=lambda s: _SESSIONS[s].get("created_at", 0)
            )
            for sid in sorted_sids[: len(_SESSIONS) - MAX_SESSIONS]:
                _SESSIONS.pop(sid, None)


ALLOWED_STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
    "favicon.ico": "image/x-icon",
}


def resolve_static_path(url_path: str) -> str | None:
    """Return an absolute file path inside PUBLIC_DIR, or None if not allowed.
    Strictly enforces an explicit allowlist of authorized frontend static assets.
    Backend code, scripts, configurations, and internal audit files are never served.
    """
    cleaned = urllib.parse.unquote(url_path).strip().split("?")[0].split("#")[0]
    relative = cleaned.lstrip("/") or "index.html"

    # Enforce strict allowlist matching
    if relative not in ALLOWED_STATIC_FILES:
        return None

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


class Operator(str):
    """Operator identity carrying name and permissions role ('approver' vs 'viewer').
    Defaults strictly to 'viewer' (least-privilege / deny by default).
    """
    def __new__(cls, name: str, role: str = "viewer"):
        obj = super().__new__(cls, name)
        obj.name = name
        obj.role = role
        return obj

_AUDIT_LOG_LOCK = threading.Lock()
_AUDIT_EVENTS: list[dict[str, Any]] = []

def record_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    """Append immutable audit entry to in-memory audit trail and disk log."""
    entry = {
        "audit_id": f"aud-{uuid.uuid4().hex[:12]}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **event
    }
    with _AUDIT_LOG_LOCK:
        _AUDIT_EVENTS.append(entry)
        if os.environ.get("ASCP_PERSIST_AUDIT_LOG", "true").lower() in ("false", "0", "no"):
            return entry
        try:
            custom_path = os.environ.get("ASCP_AUDIT_LOG_PATH")
            if custom_path:
                log_path = custom_path
                audit_dir = os.path.dirname(log_path)
            else:
                audit_dir = os.environ.get("ASCP_AUDIT_DIR") or os.path.join(BASE_DIR, "logs")
                log_path = os.path.join(audit_dir, "remediation_audit.jsonl")
            if audit_dir:
                os.makedirs(audit_dir, exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.warning("Failed to append remediation audit event: %s", exc)
        return entry


def _extract_api_token(headers: Any) -> str | None:
    """Extract API token from request headers (case-insensitive X-API-Token or Authorization Bearer)."""
    for key in ("X-API-Token", "X-Api-Token", "X-api-token", "x-api-token"):
        val = headers.get(key)
        if val:
            return val.strip()

    auth = headers.get("Authorization") or headers.get("authorization")
    if auth:
        parts = auth.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()

    return None


def resolve_operator(supplied: str, active_tokens: dict[str, Any]) -> Operator | None:
    """Map a supplied token to an Operator. Unknown or malformed entries grant nothing."""
    supplied_bytes = supplied.encode("utf-8")
    for token, entry in active_tokens.items():
        if not hmac.compare_digest(supplied_bytes, token.encode("utf-8")):
            continue
        if isinstance(entry, dict):
            user = str(entry.get("user", "")).strip()
            role = entry.get("role", "viewer")
        elif isinstance(entry, str):
            user = entry.strip()
            role = "viewer"
        else:
            return None
        if not user or role not in ("viewer", "approver"):
            return None
        return Operator(user, role=role)
    return None


class ASCPDiagnosticHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def _authenticate(self) -> Operator | None:
        """Return the operator identity for a valid API token header, else None."""
        supplied = _extract_api_token(self.headers)
        if not supplied:
            return None
        active_tokens = dict(GLOBAL_SECRET_MANAGER.get_operator_tokens())
        active_tokens.update(OPERATOR_TOKENS)
        return resolve_operator(supplied, active_tokens)

    def _read_json_body(self) -> dict[str, Any] | None:
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

    def _add_cors_headers(self):
        """Inject configurable Cross-Origin Resource Sharing headers.
        Restricts cross-origin access to explicitly permitted origins in production,
        while allowing local dev origins (localhost / 127.0.0.1) by default.
        """
        origin = self.headers.get("Origin")
        allowed_origins_env = os.environ.get("ASCP_ALLOWED_ORIGINS", "").strip()

        if allowed_origins_env:
            allowed = {o.strip() for o in allowed_origins_env.split(",") if o.strip()}
            effective_origin = origin if origin in allowed else None
        else:
            # Default development behavior: permit loopback callers or wildcard for local tools
            if origin:
                parsed = urllib.parse.urlparse(origin)
                if parsed.hostname in ("127.0.0.1", "localhost", "::1"):
                    effective_origin = origin
                else:
                    effective_origin = None
            else:
                effective_origin = "*"

        if effective_origin:
            self.send_header("Access-Control-Allow-Origin", effective_origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Token, Authorization")
            self.send_header("Access-Control-Max-Age", "86400")
            if effective_origin != "*":
                self.send_header("Vary", "Origin")

    def _add_security_headers(self, is_html: bool = False):
        """Inject defense-in-depth security headers on all HTTP responses."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if is_html:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data:; "
                "connect-src 'self' http://127.0.0.1:* http://localhost:*; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
            )
        else:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none';"
            )

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._add_security_headers()
        self._add_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._add_security_headers()
        self._add_cors_headers()
        self.end_headers()

    def do_GET(self):
        _init_default_session()
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
                sess_info = _SESSIONS.get(_ACTIVE_SESSION_ID, {})
                last_state = sess_info.get("last_state", {})
                is_remediated = bool(last_state.get("is_remediated", False))

            scenario_info = SCENARIOS.get(scen_key, SCENARIOS["ora_00054_mode6"])

            # Map scenario stage & error state to simulated pipeline state
            if is_remediated:
                sim_scenario = "healthy"
            elif scenario_info.get("st_status") == -1:
                if "Stage 1" in scenario_info.get("stage", ""):
                    sim_scenario = "stage1_stalled"
                else:
                    sim_scenario = "stage2_stalled"
            elif scenario_info.get("st_status") == 2:
                sim_scenario = "running_stage2"
            else:
                sim_scenario = scenario_info.get("lock_scenario", "healthy")

            monitor = PipelineMonitor(simulated_scenario=sim_scenario)
            registry = monitor.get_instance_registry(instance_id=scenario_info["instance_id"])
            stages = monitor.get_pipeline_stages_telemetry()
            quarantine = monitor.get_staging_quarantine_records()

            self._send_json({
                "scenario": scenario_info,
                "scenario_key": scen_key,
                "registry": vars(registry),
                "stages": stages,
                "quarantine_records": quarantine,
                "is_simulation": getattr(monitor, "simulated", True),
                "is_remediated": is_remediated
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
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            sess_id = qs.get("session_id", [None])[0] or _ACTIVE_SESSION_ID
            with _SERVER_LOCK:
                sess_info = _SESSIONS.get(sess_id, {})
                snapshot = dict(sess_info.get("last_state", {}))
            self._send_json({"session_id": sess_id, "state": snapshot})

        elif path == "/api/audit-log":
            with _AUDIT_LOG_LOCK:
                events = list(_AUDIT_EVENTS)
            self._send_json({"count": len(events), "audit_trail": events})

        elif path == "/api/metrics":
            qs = urllib.parse.parse_qs(parsed.query)
            if qs.get("format", [""])[0] == "prometheus" or "text/plain" in self.headers.get("Accept", ""):
                prom_data = GLOBAL_METRICS.to_prometheus_format().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Content-Length", str(len(prom_data)))
                self.end_headers()
                self.wfile.write(prom_data)
            else:
                self._send_json(GLOBAL_METRICS.get_summary())

        else:
            file_path = resolve_static_path(path)
            if file_path is None:
                self.send_error(404, "File not found")
                return

            guessed_type, _ = mimetypes.guess_type(file_path)
            content_type = guessed_type or "text/html; charset=utf-8"
            if content_type.startswith("text/") and "charset" not in content_type:
                content_type += "; charset=utf-8"
            elif content_type == "application/javascript":
                content_type = "application/javascript; charset=utf-8"

            with open(file_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self._add_security_headers(is_html=file_path.endswith(".html"))
            self._add_cors_headers()
            self.end_headers()
            self.wfile.write(content)

    def do_POST(self):
        global current_scenario_key, _ACTIVE_SESSION_ID, thread_counter
        _init_default_session()
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
                    _prune_expired_sessions()
                    current_scenario_key = key
                    thread_counter += 1
                    sess_id = f"sess-{uuid.uuid4().hex[:8]}"
                    new_graph = create_ascp_diagnostic_graph()
                    session_info = {
                        "graph": new_graph,
                        "thread_id": f"web-thread-{thread_counter}",
                        "scenario_key": key,
                        "session_id": sess_id,
                        "pending_approval": None,
                        "created_at": time.time(),
                        "last_state": {}
                    }
                    _SESSIONS[sess_id] = session_info
                    _ACTIVE_SESSION_ID = sess_id
                self._send_json({"success": True, "loaded_scenario": SCENARIOS[key], "session_id": sess_id})
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
            sess_id = req_data.get("session_id")

            if action != "RESUME":
                with _SERVER_LOCK:
                    _prune_expired_sessions()
                    thread_counter += 1
                    sess_id = sess_id or f"sess-{uuid.uuid4().hex[:8]}"
                    new_graph = create_ascp_diagnostic_graph()
                    scen_key = req_data.get("scenario_key") or current_scenario_key
                    current_scenario_key = scen_key
                    thread_id = f"web-thread-{thread_counter}"
                    session_info = {
                        "graph": new_graph,
                        "thread_id": thread_id,
                        "scenario_key": scen_key,
                        "session_id": sess_id,
                        "pending_approval": None,
                        "created_at": time.time(),
                        "last_state": {}
                    }
                    _SESSIONS[sess_id] = session_info
                    _ACTIVE_SESSION_ID = sess_id
            else:
                with _SERVER_LOCK:
                    sess_id = sess_id or _ACTIVE_SESSION_ID
                    session_info = _SESSIONS.get(sess_id) if sess_id else None

                if not session_info:
                    self._send_json({"error": f"Session '{sess_id}' not found or expired"}, 404)
                    return

            curr_graph = session_info["graph"]
            thread_id = session_info["thread_id"]
            scen_key = session_info["scenario_key"]

            try:
                if action == "RESUME":
                    if getattr(operator, "role", None) != "approver":
                        self._send_json({
                            "error": "Forbidden: Operator role does not have approval authority. Remediation requires an explicit approver token."
                        }, 403)
                        return

                    approved = req_data.get("approved")
                    if not isinstance(approved, bool):
                        self._send_json({"error": "'approved' must be true or false"}, 400)
                        return

                    appr_id = req_data.get("approval_id")
                    if appr_id and appr_id in _USED_APPROVAL_IDS:
                        self._send_json({"error": f"Approval '{appr_id}' has already been consumed (anti-replay check failed)"}, 409)
                        return

                    pending = session_info.get("pending_approval")
                    if not pending:
                        self._send_json({"error": "No pending HITL remediation checkpoint for this session"}, 400)
                        return

                    if not appr_id:
                        self._send_json({"error": "Missing required 'approval_id' in approval request"}, 400)
                        return

                    if appr_id != pending.get("approval_id"):
                        self._send_json({
                            "error": f"Mismatched approval ID: expected '{pending.get('approval_id')}', received '{appr_id}'"
                        }, 400)
                        return

                    # Expiration check
                    if time.time() > pending.get("expires_at", 0):
                        _remember_approval(appr_id, pending.get("expires_at", time.time() + 3600))
                        self._send_json({
                            "error": f"Approval '{appr_id}' has expired (TTL exceeded at {pending.get('expires_at_iso')})"
                        }, 400)
                        return

                    # Target action check
                    target_action = req_data.get("target_action")
                    if target_action and target_action != pending.get("action"):
                        self._send_json({
                            "error": f"Mismatched target action: expected '{pending.get('action')}', received '{target_action}'"
                        }, 400)
                        return

                    # Target SID check
                    target_sid = req_data.get("target_sid")
                    if target_sid is not None and target_sid != pending.get("target_sid"):
                        self._send_json({
                            "error": f"Mismatched target SID: expected '{pending.get('target_sid')}', received '{target_sid}'"
                        }, 400)
                        return

                    # Target object check
                    target_obj = req_data.get("target_object")
                    if target_obj and target_obj != pending.get("target_object"):
                        self._send_json({
                            "error": f"Mismatched target object: expected '{pending.get('target_object')}', received '{target_obj}'"
                        }, 400)
                        return

                    # Mark approval as used to prevent replay attacks
                    _remember_approval(appr_id, pending.get("expires_at", time.time() + 3600))
                    session_info["pending_approval"] = None

                    notes = str(req_data.get("notes", f"Decision rendered by {operator}"))[:500]
                    resume_cmd = Command(resume={
                        "approved": approved,
                        "dba_user": str(operator),
                        "approval_id": appr_id,
                        "approval_fingerprint": pending.get("approval_fingerprint"),
                        "target_action": pending.get("action"),
                        "target_sid": pending.get("target_sid"),
                        "notes": notes,
                        "approved_at": time.time()
                    })
                    with _INVOKE_LOCK:
                        state = curr_graph.invoke(
                            config={"configurable": {"thread_id": thread_id}},
                            resume_command=resume_cmd
                        )
                    record_audit_event({
                        "event_type": "HITL_REMEDIATION_APPROVAL",
                        "operator": str(operator),
                        "role": getattr(operator, "role", "viewer"),
                        "approval_id": appr_id,
                        "approval_fingerprint": pending.get("approval_fingerprint"),
                        "approved": approved,
                        "action": pending.get("action"),
                        "target_sid": pending.get("target_sid"),
                        "target_serial": pending.get("target_serial"),
                        "target_object": pending.get("target_object"),
                        "is_remediated": state.get("is_remediated"),
                        "remediation_result": state.get("remediation_result")
                    })
                    approval_created = pending.get("created_at") or session_info.get("created_at", time.time())
                    lat_secs = max(0.0, time.time() - approval_created)
                    GLOBAL_METRICS.record_approval_decision(approved, latency_seconds=lat_secs)
                    if state.get("is_remediated"):
                        tot_mttr = max(0.0, time.time() - session_info.get("created_at", time.time()))
                        GLOBAL_METRICS.record_resolution(mttr_seconds=tot_mttr, was_successful=True)
                else:
                    raw_logs = SCENARIOS.get(scen_key, SCENARIOS["ora_00054_mode6"])["logs"]
                    with _INVOKE_LOCK:
                        state = curr_graph.invoke(
                            initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": raw_logs},
                            config={"configurable": {"thread_id": thread_id}}
                        )
                    diag_duration = max(0.0, time.time() - session_info.get("created_at", time.time()))
                    GLOBAL_METRICS.record_diagnosis(duration_seconds=diag_duration)
            except Exception:
                logger.exception("Diagnostic Agent execution error")
                self._send_json({"error": "Diagnostic Agent execution failed. Check server logs."}, 500)
                return

            if state.get("interrupted") and state.get("interrupt_payload"):
                payload = dict(state.get("interrupt_payload"))
                payload.setdefault("created_at", time.time())
                session_info["pending_approval"] = payload
                GLOBAL_METRICS.record_approval_request()

            # Convert AIMessage/HumanMessage objects to serializable dicts
            serialized_msgs = []
            for msg in state.get("messages", []):
                serialized_msgs.append({
                    "role": getattr(msg, "role", "agent"),
                    "content": getattr(msg, "content", str(msg))
                })

            with _SERVER_LOCK:
                session_info["last_state"] = dict(state)
                session_info["last_state"]["messages"] = serialized_msgs
                resp_state = dict(session_info["last_state"])

            self._send_json({
                "session_id": sess_id,
                "state": resp_state,
                "interrupted": state.get("interrupted", False),
                "interrupt_payload": state.get("interrupt_payload"),
                "completed": state.get("completed", False),
                "remediation_success": state.get("is_remediated", False)
            })

        else:
            # /api/remediate removed: remediation runs only through the graph's HITL gate.
            self._send_json({"error": "Endpoint not found"}, 404)


def run_server(port: int = 8085, host: str = "127.0.0.1"):
    _init_default_session()
    active_tokens = dict(GLOBAL_SECRET_MANAGER.get_operator_tokens())
    active_tokens.update(OPERATOR_TOKENS)
    env_mode = os.environ.get("ASCP_ENV", "production").lower()
    is_loopback = host in ("127.0.0.1", "localhost", "::1")
    is_dev = env_mode in ("development", "dev", "local")

    if not active_tokens:
        if not is_dev or not is_loopback:
            raise RuntimeError(
                f"CRITICAL SECURITY CONFIGURATION ERROR: ASCP_OPERATOR_TOKENS must be set when running in "
                f"non-local or production environment (ASCP_ENV='{env_mode}', host='{host}'). "
                f"Refusing to generate or fallback to dev tokens."
            )
        dev_token = os.environ.get("ASCP_DEV_TOKEN") or std_secrets.token_urlsafe(32)
        logger.warning("SECURITY WARNING: ASCP_OPERATOR_TOKENS not specified. Using development token.")
        print("[!] SECURITY WARNING: ASCP_OPERATOR_TOKENS not specified in environment.")
        print(f"[+] Dev operator token (this run only): {dev_token}")
        OPERATOR_TOKENS[dev_token] = {"user": "local-developer", "role": "approver"}
        active_tokens[dev_token] = {"user": "local-developer", "role": "approver"}
    with ThreadedASCPDiagnosticServer((host, port), ASCPDiagnosticHandler) as httpd:
        print(f"[+] Multi-Threaded ASCP Diagnostic Dashboard running on http://{host}:{port}")
        httpd.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.getenv("PORT", "8085"))
    host = os.getenv("HOST", "127.0.0.1")
    run_server(port, host)
