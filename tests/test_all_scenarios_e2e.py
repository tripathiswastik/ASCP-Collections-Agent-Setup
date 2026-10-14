"""Self-contained End-to-End Integration Tests for all failure catalog scenarios.
Spins up a lightweight ThreadedASCPDiagnosticServer on an ephemeral port via pytest fixture,
waits for readiness, and runs end-to-end diagnosis and HITL remediation across all scenarios.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from typing import Any

import pytest

import web.server as server_mod
from web.server import ASCPDiagnosticHandler, ThreadedASCPDiagnosticServer


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def e2e_server():
    """Module-scoped fixture starting an isolated in-process ASCP diagnostic server.
    Waits for server readiness before yielding, and gracefully shuts down after tests complete.
    """
    port = find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    token = "test-approver-token-e2e"

    orig_tokens = server_mod.OPERATOR_TOKENS
    server_mod.OPERATOR_TOKENS = {
        token: {"user": "e2e_test_dba", "role": "approver"}
    }

    httpd = ThreadedASCPDiagnosticServer(("127.0.0.1", port), ASCPDiagnosticHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    # Wait for server readiness
    ready = False
    start_time = time.time()
    while time.time() - start_time < 5.0:
        try:
            req = urllib.request.Request(
                f"{base_url}/api/status",
                headers={"Authorization": f"Bearer {token}"}
            )
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    ready = True
                    break
        except (urllib.error.URLError, OSError):
            time.sleep(0.1)

    if not ready:
        httpd.shutdown()
        httpd.server_close()
        server_mod.OPERATOR_TOKENS = orig_tokens
        pytest.fail(f"ASCP Diagnostic test server failed to reach readiness at {base_url} within 5s")

    yield {"base_url": base_url, "token": token}

    # Teardown
    server_mod.OPERATOR_TOKENS = orig_tokens
    httpd.shutdown()
    httpd.server_close()


def _request(base_url: str, token: str, path: str, method: str = "GET", data: dict | None = None) -> dict[str, Any]:
    url = f"{base_url}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    body = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


@pytest.mark.integration
def test_all_catalog_scenarios_e2e(e2e_server):
    """Execute end-to-end diagnosis and HITL approval workflow across all 11 failure scenarios."""
    base_url = e2e_server["base_url"]
    token = e2e_server["token"]

    scenarios_resp = _request(base_url, token, "/api/scenarios")
    assert "scenarios" in scenarios_resp
    scenarios = [s["key"] for s in scenarios_resp["scenarios"]]
    assert len(scenarios) >= 11, f"Expected at least 11 scenarios, found {len(scenarios)}"

    results = []

    for scen_key in scenarios:
        # 1. Load scenario
        load_res = _request(base_url, token, "/api/scenario/load", "POST", {"key": scen_key})
        assert "loaded_scenario" in load_res
        scen_name = load_res["loaded_scenario"]["name"]

        # 2. Check initial status
        st1 = _request(base_url, token, "/api/status")
        pre_st = st1["registry"]["st_status"]

        # 3. Parse logs
        raw_logs = st1["scenario"]["logs"]
        parse_res = _request(base_url, token, "/api/parse-log", "POST", {"log_text": "\n".join(raw_logs)})
        assert "results" in parse_res
        clusters = len(parse_res.get("results", []))

        # 4. Run Diagnosis
        diag = _request(base_url, token, "/api/diagnose", "POST", {"action": "START", "scenario_key": scen_key})
        interrupted = diag.get("interrupted", False)
        completed = diag.get("completed", False)
        rem_success = diag.get("remediation_success", False)
        sess_id = diag.get("session_id")
        assert sess_id is not None

        # 5. If interrupted at HITL Gate, approve with valid token and fingerprint
        if interrupted:
            pay = diag.get("interrupt_payload", {})
            appr_id = pay.get("approval_id")
            action_name = pay.get("action")
            assert appr_id is not None, f"Scenario {scen_key} interrupted without approval_id"

            resume = _request(base_url, token, "/api/diagnose", "POST", {
                "action": "RESUME",
                "session_id": sess_id,
                "approved": True,
                "approval_id": appr_id,
                "target_action": action_name,
                "target_sid": pay.get("target_sid"),
                "target_serial": pay.get("target_serial"),
                "target_object": pay.get("target_object"),
                "dba_user": "DBA_E2E_OPERATOR"
            })
            completed = resume.get("completed", False)
            rem_success = resume.get("remediation_success", False)

        # 6. Check post-diagnosis status
        st2 = _request(base_url, token, "/api/status")
        post_st = st2["registry"]["st_status"]
        is_rem_post = st2["is_remediated"]

        assert completed, f"Scenario {scen_key} did not complete execution"
        results.append({
            "key": scen_key,
            "name": scen_name,
            "clusters": clusters,
            "interrupted": interrupted,
            "completed": completed,
            "rem_success": rem_success,
            "pre_st": pre_st,
            "post_st": post_st,
            "is_rem_post": is_rem_post,
        })

    assert len(results) == len(scenarios)
