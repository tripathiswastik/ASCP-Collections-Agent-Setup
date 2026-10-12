# tests/test_security_fixes.py
import os
import unittest
from unittest import mock

try:
    import pytest
except ImportError:
    class _PytestShim:
        class raises:
            def __init__(self, expected_exc):
                self.expected_exc = expected_exc

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                if exc_type is None:
                    raise AssertionError(f"Expected {self.expected_exc.__name__} but no exception was raised.")
                return issubclass(exc_type, self.expected_exc)
    pytest = _PytestShim()

from ascp_agent.config import OracleConfig, ServiceNowConfig
from ascp_agent.guardrails import EnterpriseGuardrails, SecurityViolationError
from ascp_agent.itsm_service_now import ServiceNowClient
from ascp_agent.remediation import format_kill_session_sql, format_snapshot_refresh_sql
from web.server import resolve_static_path


def test_kill_sql_normal_input():
    assert format_kill_session_sql(412, 28419) == "ALTER SYSTEM KILL SESSION '412,28419' IMMEDIATE"


def test_kill_sql_rejects_injection_string():
    with pytest.raises(ValueError):
        format_kill_session_sql("1,2' IMMEDIATE; DROP TABLE x; --", 3)


def test_snapshot_refresh_rejects_bad_identifier():
    with pytest.raises(ValueError):
        format_snapshot_refresh_sql("X'); DROP TABLE Y; --")


def test_guardrail_denies_unlisted_statement():
    with pytest.raises(SecurityViolationError):
        EnterpriseGuardrails().validate_sql_command("DELETE FROM MSC_ST_DEMANDS")


def test_guardrail_allows_select_and_exact_kill():
    guardrails = EnterpriseGuardrails()
    assert guardrails.validate_sql_command("SELECT sid FROM v$session") is True
    assert guardrails.validate_sql_command("ALTER SYSTEM KILL SESSION '412,28419' IMMEDIATE") is True


def test_static_path_blocks_traversal():
    assert resolve_static_path("/../ascp_agent/config.py") is None


def test_live_oracle_config_requires_password(monkeypatch=None):
    if monkeypatch:
        monkeypatch.setenv("ORACLE_SIMULATION", "false")
        monkeypatch.delenv("ORACLE_PASSWORD", raising=False)
        with pytest.raises(RuntimeError):
            OracleConfig()
    else:
        orig_sim = os.environ.get("ORACLE_SIMULATION")
        orig_pwd = os.environ.get("ORACLE_PASSWORD")
        try:
            os.environ["ORACLE_SIMULATION"] = "false"
            os.environ.pop("ORACLE_PASSWORD", None)
            with pytest.raises(RuntimeError):
                OracleConfig()
        finally:
            if orig_sim is not None:
                os.environ["ORACLE_SIMULATION"] = orig_sim
            else:
                os.environ.pop("ORACLE_SIMULATION", None)
            if orig_pwd is not None:
                os.environ["ORACLE_PASSWORD"] = orig_pwd
            else:
                os.environ.pop("ORACLE_PASSWORD", None)


def test_dispatch_reports_failed_not_simulated():
    config = ServiceNowConfig()
    config.dry_run = False
    config.enabled = True
    client = ServiceNowClient(config)
    with mock.patch("requests.Session.post", return_value=mock.Mock(status_code=401)):
        result = client.dispatch_incident({"short_description": "test"})
    assert result["status"] == "FAILED"


class TestSecurityFixes(unittest.TestCase):
    def test_kill_sql_normal_input(self):
        test_kill_sql_normal_input()

    def test_kill_sql_rejects_injection_string(self):
        test_kill_sql_rejects_injection_string()

    def test_snapshot_refresh_rejects_bad_identifier(self):
        test_snapshot_refresh_rejects_bad_identifier()

    def test_guardrail_denies_unlisted_statement(self):
        test_guardrail_denies_unlisted_statement()

    def test_guardrail_allows_select_and_exact_kill(self):
        test_guardrail_allows_select_and_exact_kill()

    def test_static_path_blocks_traversal(self):
        test_static_path_blocks_traversal()

    def test_live_oracle_config_requires_password(self):
        test_live_oracle_config_requires_password()

    def test_dispatch_reports_failed_not_simulated(self):
        test_dispatch_reports_failed_not_simulated()
