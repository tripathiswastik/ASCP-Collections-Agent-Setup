"""HTTP-Level Authentication, Role-Based Access Control, and Server Security Tests.
Tests real HTTP request/response exchanges against a live ThreadedASCPDiagnosticServer:
1. Missing X-API-Token -> 401 Unauthorized
2. Wrong X-API-Token -> 401 Unauthorized
3. Forged Referer Header -> 401 Unauthorized
4. Query String Token Leak Attempt -> 401 Unauthorized
5. Viewer Role Permissions (Read/Diagnose Allowed = 200, Remediation Approval Forbidden = 403)
6. Approver Role Permissions (Remediation Approval Allowed = 200)
7. Anti-Replay Idempotency at HTTP layer (Replayed approval returns 409)
8. Append-Only Audit Log endpoint verification
"""

import unittest
import urllib.request
import urllib.error
import json
import threading
import socket
import time
import web.server as server_mod
from web.server import ThreadedASCPDiagnosticServer, ASCPDiagnosticHandler


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestHttpAuthAndRoles(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.port = find_free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.orig_tokens = server_mod.OPERATOR_TOKENS

        # Configure role-based operator tokens
        server_mod.OPERATOR_TOKENS = {
            "viewer-secret-123": {"user": "analyst_bob", "role": "viewer"},
            "approver-secret-456": {"user": "lead_dba_alice", "role": "approver"}
        }

        cls.httpd = ThreadedASCPDiagnosticServer(("127.0.0.1", cls.port), ASCPDiagnosticHandler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        server_mod.OPERATOR_TOKENS = cls.orig_tokens
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _http_req(self, path: str, method: str = "GET", headers: dict = None, body: dict = None):
        url = f"{self.base_url}{path}"
        req_headers = headers.copy() if headers else {}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                body_parsed = json.loads(exc.read().decode("utf-8"))
            except Exception:
                body_parsed = {"raw": exc.reason}
            return exc.code, body_parsed

    def test_missing_token_returns_401(self):
        status, data = self._http_req("/api/status")
        self.assertEqual(status, 401)
        self.assertIn("error", data)

    def test_wrong_token_returns_401(self):
        status, data = self._http_req("/api/status", headers={"X-API-Token": "invalid-secret-xyz"})
        self.assertEqual(status, 401)

    def test_forged_referer_returns_401(self):
        status, data = self._http_req("/api/status", headers={
            "Referer": "http://127.0.0.1:8085/index.html"
        })
        self.assertEqual(status, 401)

    def test_query_string_token_rejected_as_401(self):
        status, data = self._http_req("/api/status?token=approver-secret-456")
        self.assertEqual(status, 401)

    def test_viewer_role_can_read_telemetry(self):
        status, data = self._http_req("/api/status", headers={"X-API-Token": "viewer-secret-123"})
        self.assertEqual(status, 200)
        self.assertIn("registry", data)
        self.assertIn("stages", data)

    def test_viewer_role_forbidden_from_remediation_approval_403(self):
        # 1. Trigger diagnosis to reach HITL gate
        status, diag = self._http_req(
            "/api/diagnose",
            method="POST",
            headers={"X-API-Token": "viewer-secret-123"},
            body={"action": "START"}
        )
        self.assertEqual(status, 200)
        self.assertTrue(diag.get("interrupted"))
        appr_id = diag["interrupt_payload"]["approval_id"]
        sess_id = diag.get("session_id")

        # 2. Viewer attempts to approve -> HTTP 403 Forbidden
        status, res = self._http_req(
            "/api/diagnose",
            method="POST",
            headers={"X-API-Token": "viewer-secret-123"},
            body={
                "action": "RESUME",
                "session_id": sess_id,
                "approval_id": appr_id,
                "approved": True
            }
        )
        self.assertEqual(status, 403)
        self.assertIn("Forbidden", res.get("error", ""))

    def test_approver_role_allowed_remediation_and_anti_replay(self):
        # 1. Start diagnosis with approver token
        status, diag = self._http_req(
            "/api/diagnose",
            method="POST",
            headers={"X-API-Token": "approver-secret-456"},
            body={"action": "START"}
        )
        self.assertEqual(status, 200)
        self.assertTrue(diag.get("interrupted"))
        appr_id = diag["interrupt_payload"]["approval_id"]
        sess_id = diag.get("session_id")

        # 2. Approver submits valid approval -> HTTP 200 OK
        status, res = self._http_req(
            "/api/diagnose",
            method="POST",
            headers={"X-API-Token": "approver-secret-456"},
            body={
                "action": "RESUME",
                "session_id": sess_id,
                "approval_id": appr_id,
                "approved": True
            }
        )
        self.assertEqual(status, 200)
        self.assertTrue(res.get("completed"))
        self.assertTrue(res.get("remediation_success"))

        # 3. Anti-Replay: Attempt to replay consumed approval ID -> HTTP 409 Conflict
        status, replay_res = self._http_req(
            "/api/diagnose",
            method="POST",
            headers={"X-API-Token": "approver-secret-456"},
            body={
                "action": "RESUME",
                "session_id": sess_id,
                "approval_id": appr_id,
                "approved": True
            }
        )
        self.assertEqual(status, 409)
        self.assertIn("anti-replay", replay_res.get("error", "").lower())

        # 4. Check audit log has recorded the event
        status, audit = self._http_req("/api/audit-log", headers={"X-API-Token": "approver-secret-456"})
        self.assertEqual(status, 200)
        self.assertGreater(audit.get("count", 0), 0)
        latest_audit = audit["audit_trail"][-1]
        self.assertEqual(latest_audit.get("operator"), "lead_dba_alice")
        self.assertEqual(latest_audit.get("role"), "approver")
        self.assertEqual(latest_audit.get("approval_id"), appr_id)


if __name__ == "__main__":
    unittest.main()
