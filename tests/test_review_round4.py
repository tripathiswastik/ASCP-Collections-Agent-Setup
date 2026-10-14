"""Validation tests for Round 4 review findings:
1. --token flag in live harness
2. No hardcoded public tokens in scripts or workflows
3. Mandatory approval for EXTEND_UNDO_RETENTION
4. Incident skipping for healthy pipeline
5. Contextual recovery command in ServiceNow messages
"""

import subprocess
import sys
from pathlib import Path

from ascp_agent.graph import create_ascp_diagnostic_graph
from ascp_agent.hitl_governance import HITLGovernanceEngine
from ascp_agent.simulator import SCENARIOS

ROOT = Path(__file__).resolve().parents[1]


def _run(scenario_key: str, thread_id: str):
    graph = create_ascp_diagnostic_graph()
    return graph.invoke(
        initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": SCENARIOS[scenario_key]["logs"]},
        config={"configurable": {"thread_id": thread_id}},
    )


def test_live_harness_accepts_token_flag():
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "run_55_live_runs.py"), "--help"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert "--token" in out.stdout


def test_no_hardcoded_public_token_in_scripts_or_workflows():
    files = list((ROOT / "scripts").glob("*.py")) + list((ROOT / ".github" / "workflows").glob("*.yml"))
    offenders = [f.name for f in files if "dev-operator-secret-token" in f.read_text(errors="ignore")]
    assert offenders == []


def test_undo_retention_requires_approval():
    assert HITLGovernanceEngine.evaluate_governance_routing("EXTEND_UNDO_RETENTION", 99.0) == "MANDATORY_HITL_INTERRUPT"


def test_healthy_pipeline_opens_no_incident():
    state = _run("healthy_pipeline", "t-healthy")
    assert state["servicenow_incident"]["status"] == "SKIPPED"


def test_st_status_text_only_for_reset_actions():
    state = _run("ora_01555_snapshot_old", "t-undo")
    assert "ST_STATUS" not in state["messages"][-1].content


def test_live_harness_cli_missing_token_fails_safely():
    import os
    env = dict(os.environ)
    env.pop("E2E_TOKEN", None)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "run_55_live_runs.py"), "-c", "1"],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
        check=False,
    )
    assert proc.returncode == 2
    assert "No API token provided" in proc.stderr or "No API token provided" in proc.stdout


def test_validate_operator_tokens_rejects_placeholders():
    import pytest

    from web.server import validate_operator_tokens

    bad_tokens = {
        "REPLACE_WITH_STRONG_RANDOM_APPROVER_TOKEN": {"user": "alice", "role": "approver"}
    }
    with pytest.raises(ValueError, match="Placeholder token"):
        validate_operator_tokens(bad_tokens)

    bad_tokens2 = {
        "my-placeholder-token-123": {"user": "alice", "role": "approver"}
    }
    with pytest.raises(ValueError, match="Placeholder token"):
        validate_operator_tokens(bad_tokens2)


def test_validate_operator_tokens_rejects_invalid_role():
    import pytest

    from web.server import validate_operator_tokens

    invalid_role_tokens = {
        "strong-token-xyz-123456": {"user": "alice", "role": "superuser"}
    }
    with pytest.raises(ValueError, match="Invalid role"):
        validate_operator_tokens(invalid_role_tokens)


def test_validate_operator_tokens_accepts_valid_config():
    from web.server import validate_operator_tokens

    valid_tokens = {
        "tok-approver-77a8b9c0": {"user": "lead_dba", "role": "approver"},
        "tok-viewer-11223344": {"user": "reader", "role": "viewer"},
    }
    validated = validate_operator_tokens(valid_tokens)
    assert len(validated) == 2
    assert validated["tok-approver-77a8b9c0"]["role"] == "approver"
    assert validated["tok-viewer-11223344"]["role"] == "viewer"


def test_clean_release_archive_hygiene():
    import zipfile

    from scripts.package_release import ARCHIVE_PATH, build_release_zip

    if not ARCHIVE_PATH.exists():
        build_release_zip()

    with zipfile.ZipFile(ARCHIVE_PATH, "r") as zf:
        names = zf.namelist()
        for name in names:
            parts = Path(name).parts
            assert ".git" not in parts, f"Forbidden .git in release: {name}"
            assert not name.endswith(".pyc"), f"Forbidden .pyc in release: {name}"
            assert not name.endswith(".jsonl"), f"Forbidden audit log in release: {name}"
            assert "__pycache__" not in parts, f"Forbidden cache in release: {name}"
            assert "logs" not in parts, f"Forbidden logs folder in release: {name}"
            assert not name.endswith("/.env"), f"Forbidden .env in release: {name}"
            assert not name.endswith("config/secrets.json"), f"Forbidden secrets.json in release: {name}"
