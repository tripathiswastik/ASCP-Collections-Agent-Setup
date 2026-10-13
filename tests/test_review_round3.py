# tests/test_review_round3.py
from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace

import pytest

from ascp_agent.guarded_remediation import GuardedRemediationLayer
from ascp_agent.lock_engine import LockDiagnosticsEngine
from web import server


def test_plain_string_token_is_viewer():
    operator = server.resolve_operator("t", {"t": "bob"})
    assert operator is not None
    assert operator.role == "viewer"


def test_name_does_not_decide_role():
    op = server.resolve_operator("t", {"t": "interviewer_amy"})
    assert op is not None
    assert op.role == "viewer"
    explicit = {"t": {"user": "interviewer_amy", "role": "approver"}}
    op_exp = server.resolve_operator("t", explicit)
    assert op_exp is not None
    assert op_exp.role == "approver"


def test_malformed_or_unknown_token_grants_nothing():
    assert server.resolve_operator("t", {"t": {"role": "approver"}}) is None
    assert server.resolve_operator("wrong", {"t": "bob"}) is None


def test_run_server_refuses_without_tokens_by_default(monkeypatch):
    monkeypatch.delenv("ASCP_ENV", raising=False)
    monkeypatch.delenv("ASCP_OPERATOR_TOKENS", raising=False)
    monkeypatch.setattr(server, "OPERATOR_TOKENS", {})
    with pytest.raises(RuntimeError):
        server.run_server(port=0)


def _proposal(action, target):
    return SimpleNamespace(
        action=action,
        target=target,
        requires_approval=False,
        approval_status="APPROVED",
        expires_at_unix=4_000_000_000,
        verification_check="SELECT 1 FROM DUAL",
    )


def test_unknown_action_is_not_reported_as_executed():
    layer = GuardedRemediationLayer()
    layer._active_proposals["P1"] = _proposal("CMCLEAN_EXEC", {})
    outcome = layer.execute_guarded("P1")
    assert outcome.executed is False
    assert outcome.success is False


def test_kill_recheck_passes_inst_id(monkeypatch):
    seen = []

    def fake_verify(self, sid, serial, inst_id=None):
        seen.append(inst_id)
        return None  # noqa: RET501, PLR1711

    monkeypatch.setattr(LockDiagnosticsEngine, "verify_session_active", fake_verify)
    layer = GuardedRemediationLayer()
    layer._active_proposals["P2"] = _proposal(
        "KILL_SESSION", {"sid": 412, "serial_number": 28419, "inst_id": 2}
    )
    layer.execute_guarded("P2")
    assert seen == [2]


def test_pytest_collection_needs_no_running_server():
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout[-400:]
