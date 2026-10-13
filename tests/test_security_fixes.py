from __future__ import annotations

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
from ascp_agent.graph import hitl_gate_node
from ascp_agent.guardrails import EnterpriseGuardrails, SecurityViolationError
from ascp_agent.hitl_governance import HITLGovernanceEngine
from ascp_agent.itsm_service_now import ServiceNowClient
from ascp_agent.remediation import RemediationEngine, format_kill_session_sql, format_snapshot_refresh_sql
from ascp_agent.state import DiagnosticState
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


def test_guardrail_blocks_piggybacked_plsql():
    sql = "BEGIN DBMS_PIPE.PURGE('X'); EXECUTE IMMEDIATE 'DROP USER SCOTT CASCADE'; END;"
    with pytest.raises(SecurityViolationError):
        EnterpriseGuardrails().validate_sql_command(sql)


def test_guardrail_allows_exact_purge_call():
    sql = "BEGIN MSC_CL_COLLECTION.PURGE_STAGING_TABLES_SUB(p_instance_id => 1001, p_validation => 'N'); END;"
    assert EnterpriseGuardrails().validate_sql_command(sql) is True


def test_mandatory_approval_actions_never_auto_execute():
    assert HITLGovernanceEngine.evaluate_governance_routing("RESET_PIPE", 99.0) == "MANDATORY_HITL_INTERRUPT"


def test_unwired_action_does_not_report_success():
    state = DiagnosticState({
        "remediation_action": "CMCLEAN_EXEC", "confidence_score": 95.0, "risk_level": "HIGH",
        "remediation_approved": True, "human_response": {"approved": True, "dba_user": "alice"},
    })
    result = hitl_gate_node(state)
    assert result["is_remediated"] is False
    assert "nothing was run" in result["messages"][0].content


def test_purge_no_validation_runs_registry_reset():
    result = RemediationEngine().execute_purge_staging_no_validation(1001)
    assert "UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0" in result.command_executed
    assert result.audit_record["normalized_st_status"] == 0


def test_server_has_no_default_tokens(monkeypatch=None):
    if monkeypatch:
        monkeypatch.delenv("ASCP_OPERATOR_TOKENS", raising=False)
        import importlib

        from web import server
        importlib.reload(server)
        assert server.OPERATOR_TOKENS == {}
    else:
        orig = os.environ.get("ASCP_OPERATOR_TOKENS")
        try:
            os.environ.pop("ASCP_OPERATOR_TOKENS", None)
            import importlib

            from web import server
            importlib.reload(server)
            assert server.OPERATOR_TOKENS == {}
        finally:
            if orig is not None:
                os.environ["ASCP_OPERATOR_TOKENS"] = orig
            else:
                os.environ.pop("ASCP_OPERATOR_TOKENS", None)


def test_undo_check_is_not_a_stub_in_live_mode():
    engine = RemediationEngine(connection_config=type("Cfg", (), {"use_simulation": False})())
    with pytest.raises(NotImplementedError):
        engine.execute_kill_session(412, 28419, "MSC_ST_DEMANDS")


def test_query_failure_is_not_masked_as_simulation(monkeypatch=None):
    from ascp_agent.db import OracleConnectionPool
    pool = OracleConnectionPool()
    if monkeypatch:
        monkeypatch.setattr(OracleConnectionPool, "is_simulation", property(lambda self: False))
        monkeypatch.setattr(pool, "get_connection", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
        with pytest.raises(Exception):
            pool.execute_query("SELECT 1 FROM DUAL")
    else:
        orig_is_sim = OracleConnectionPool.is_simulation
        orig_get_conn = pool.get_connection
        try:
            OracleConnectionPool.is_simulation = property(lambda self: False)
            def _failing_conn():
                raise RuntimeError("db down")
                yield
            pool.get_connection = _failing_conn
            with pytest.raises(Exception):
                pool.execute_query("SELECT 1 FROM DUAL")
        finally:
            OracleConnectionPool.is_simulation = orig_is_sim
            pool.get_connection = orig_get_conn


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

    def test_guardrail_blocks_piggybacked_plsql(self):
        test_guardrail_blocks_piggybacked_plsql()

    def test_guardrail_allows_exact_purge_call(self):
        test_guardrail_allows_exact_purge_call()

    def test_mandatory_approval_actions_never_auto_execute(self):
        test_mandatory_approval_actions_never_auto_execute()

    def test_unwired_action_does_not_report_success(self):
        test_unwired_action_does_not_report_success()

    def test_purge_no_validation_runs_registry_reset(self):
        test_purge_no_validation_runs_registry_reset()

    def test_server_has_no_default_tokens(self):
        test_server_has_no_default_tokens()

    def test_undo_check_is_not_a_stub_in_live_mode(self):
        test_undo_check_is_not_a_stub_in_live_mode()

    def test_query_failure_is_not_masked_as_simulation(self):
        test_query_failure_is_not_masked_as_simulation()
