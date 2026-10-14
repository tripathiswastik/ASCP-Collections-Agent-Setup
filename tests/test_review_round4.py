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
