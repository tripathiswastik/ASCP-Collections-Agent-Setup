"""End-to-End Integration Tests across all failure catalog scenarios.
Guarded by RUN_E2E=1 so unit test discovery never attempts network I/O or blocks in CI.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from typing import Any

TOKEN = os.getenv("E2E_TOKEN", "e2e-approver-secret-token")
BASE_URL = os.getenv("E2E_BASE_URL", "http://127.0.0.1:8085")


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def req(base_url: str, token: str, path_or_url: str, method: str = "GET", data: dict | None = None) -> dict[str, Any]:
    url = path_or_url if path_or_url.startswith("http") else f"{base_url}{path_or_url}"
    headers = {"Authorization": f"Bearer {token}"}
    body = json.dumps(data).encode("utf-8") if data is not None else None
    if data is not None:
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(r, timeout=10.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


@unittest.skipUnless(os.getenv("RUN_E2E", "0") == "1", "E2E tests disabled by default (opt-in with RUN_E2E=1)")
class TestAllScenariosE2E(unittest.TestCase):
    """End-to-End scenario verification running when explicitly enabled via RUN_E2E=1."""

    base_url = BASE_URL
    token = TOKEN
    httpd = None
    server_thread = None

    @classmethod
    def setUpClass(cls):
        # 1. Probe if external server is already reachable
        try:
            r = urllib.request.Request(
                f"{cls.base_url}/api/status",
                headers={"Authorization": f"Bearer {cls.token}"}
            )
            with urllib.request.urlopen(r, timeout=1.0) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

        # 2. Start local in-process server if external server not running
        import web.server as server_mod
        from web.server import ASCPDiagnosticHandler, ThreadedASCPDiagnosticServer

        port = find_free_port()
        cls.base_url = f"http://127.0.0.1:{port}"
        server_mod.OPERATOR_TOKENS[cls.token] = {"user": "e2e_operator", "role": "approver"}

        cls.httpd = ThreadedASCPDiagnosticServer(("127.0.0.1", port), ASCPDiagnosticHandler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()

        # Wait for readiness
        ready = False
        start_time = time.time()
        while time.time() - start_time < 5.0:
            try:
                check_req = urllib.request.Request(
                    f"{cls.base_url}/api/status",
                    headers={"Authorization": f"Bearer {cls.token}"}
                )
                with urllib.request.urlopen(check_req, timeout=1.0) as resp:
                    if resp.status == 200:
                        ready = True
                        break
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(0.1)

        if not ready:
            cls.tearDownClass()
            raise RuntimeError(f"In-process ASCP Diagnostic test server failed to reach readiness at {cls.base_url}")

    @classmethod
    def tearDownClass(cls):
        if cls.httpd is not None:
            cls.httpd.shutdown()
            cls.httpd.server_close()
            cls.httpd = None

    def test_all_catalog_scenarios_e2e(self):
        """Execute diagnosis and HITL approval across all 11 catalog failure scenarios."""
        scenarios_resp = req(self.base_url, self.token, "/api/scenarios")
        self.assertIn("scenarios", scenarios_resp)
        scenarios = [s["key"] for s in scenarios_resp["scenarios"]]
        self.assertGreaterEqual(len(scenarios), 11)

        for scen_key in scenarios:
            # 1. Load scenario
            load_res = req(self.base_url, self.token, "/api/scenario/load", "POST", {"key": scen_key})
            self.assertIn("loaded_scenario", load_res)

            # 2. Check initial status
            st1 = req(self.base_url, self.token, "/api/status")
            self.assertIn("registry", st1)

            # 3. Parse logs
            raw_logs = st1["scenario"]["logs"]
            parse_res = req(self.base_url, self.token, "/api/parse-log", "POST", {"log_text": "\n".join(raw_logs)})
            self.assertIn("results", parse_res)

            # 4. Run Diagnosis
            diag = req(self.base_url, self.token, "/api/diagnose", "POST", {"action": "START", "scenario_key": scen_key})
            interrupted = diag.get("interrupted", False)
            completed = diag.get("completed", False)
            sess_id = diag.get("session_id")
            self.assertIsNotNone(sess_id)

            # 5. If interrupted at HITL Gate, approve
            if interrupted:
                pay = diag.get("interrupt_payload", {})
                appr_id = pay.get("approval_id")
                action_name = pay.get("action")
                self.assertIsNotNone(appr_id)

                resume = req(self.base_url, self.token, "/api/diagnose", "POST", {
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

            # 6. Check post-diagnosis status
            st2 = req(self.base_url, self.token, "/api/status")
            self.assertIn("registry", st2)
            self.assertTrue(completed, f"Scenario {scen_key} did not complete execution")


if __name__ == "__main__":
    unittest.main()
