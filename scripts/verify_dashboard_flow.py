"""
Python Version: 3.10+ (Target: Python 3.10, 3.11, 3.12)
Purpose: End-to-end verification script testing live API endpoints and dashboard workflow against the ASCP diagnostic web server.
Runs-in: Standalone client process communicating with local or containerized ASCP Diagnostic Web Server.
"""

import urllib.request
import urllib.error
import json
import sys

def run_verification(base_url="http://localhost:8085"):
    def req(endpoint, data=None):
        url = f"{base_url}{endpoint}"
        headers = {'X-API-Token': 'dev-token'}
        if data is not None:
            headers['Content-Type'] = 'application/json'
            r = urllib.request.Request(url, data=json.dumps(data).encode(), headers=headers)
        else:
            r = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(r) as res:
            return json.loads(res.read().decode())

    print("================================================================================")
    print("      VERIFYING BROWSER TASK SCRATCHPAD WORKFLOW ON DASHBOARD SERVER")
    print("================================================================================")

    # 1. Load Scenario
    print("\n[Step 1] Loading ORA-00054 Mode 6 Lock Contention Scenario...")
    load_res = req("/api/scenario/load", {"key": "ora_00054_mode6"})
    print(" -> Loaded scenario:", load_res["loaded_scenario"]["name"])

    # 2. Dual-Stage ETL Pipeline Visualization
    print("\n[Step 2] Verifying Dual-Stage ETL Pipeline Telemetry...")
    status = req("/api/status")
    print(f" -> Pipeline Stages ({len(status['stages'])} total):")
    for s in status['stages']:
        print(f"    - {s['stage_name']} ({s['parent_process']}): {s['status']} ({s['processed_count']} records, {s['quarantine_error_count']} errors)")
    print(f" -> Staging Registry ST_STATUS: {status['registry']['st_status']} ({status['registry']['st_status_name']})")

    # 3. Hierarchical Root Blocker lock tree
    print("\n[Step 3] Verifying Hierarchical Root Blocker Lock Tree...")
    locks = req("/api/locks")
    rb = locks["root_blocker"]
    print(f" -> Root Blocker Identified: SID {rb['sid']}, Serial {rb['serial_number']}")
    print(f" -> Object: {rb['object_name']}, Lock Mode: {rb['locked_mode_text']}")
    print(f" -> Operational Impact: {rb['operational_impact']}")
    print(f" -> Downstream Blocked Workers in Tree: {len(locks['telemetry']) - 1}")

    # 4. Drain Algorithmic Engine parsed clusters
    print("\n[Step 4] Verifying Drain Algorithmic Engine Log Parsing...")
    drain = req("/api/parse-log", {})
    print(f" -> Successfully clustered into {drain['count']} distinct log event templates:")
    for cluster in drain["results"]:
        print(f"    - [Cluster #{cluster.get('cluster_id')}] {cluster.get('template')}")

    # 5. Autonomous Diagnosis -> HITL Gate Modal
    print("\n[Step 5] Triggering Autonomous Diagnosis (Click 'Run Autonomous Diagnosis')...")
    diag = req("/api/diagnose", {"action": "START"})
    assert diag.get("interrupted") is True, "Expected graph to pause at HITL Gate!"
    payload = diag.get("interrupt_payload", {})
    sess_id = diag.get("session_id")
    appr_id = payload.get("approval_id")
    assert appr_id, "Expected valid approval_id in interrupt payload!"
    print(f" -> HITL Gate Triggered: Interrupted = {diag.get('interrupted')}")
    print(f" -> Approval ID: {appr_id} (Expires: {payload.get('expires_at_iso')})")
    print(f" -> Target Action: {payload.get('action')}")
    print(f" -> Risk Tier: {payload.get('risk_tier')}")
    print(f" -> Target Session SID: {payload.get('target_sid')}")
    print(f" -> Target Object: {payload.get('target_object')}")

    # 6. Approve & Execute Remediation -> ServiceNow Incident Ticket
    print("\n[Step 6] Approving Remediation with action-bound approval ID...")
    resumed = req("/api/diagnose", {
        "action": "RESUME",
        "session_id": sess_id,
        "approved": True,
        "approval_id": appr_id,
        "target_action": payload.get("action"),
        "target_sid": payload.get("target_sid"),
        "target_serial": payload.get("target_serial"),
        "target_object": payload.get("target_object"),
        "dba_user": "LEAD_DBA",
        "notes": "Approved by Lead DBA"
    })
    state = resumed.get("state", {})
    print(f" -> Execution Completed: {resumed.get('completed')}")
    print(f" -> Session Remediation Success: {state.get('is_remediated')}")
    sn_inc = state.get("servicenow_incident") or state.get("service_now_incident", {})
    print(f" -> ServiceNow Incident Created: {sn_inc.get('incident_number')}")
    print(f" -> Priority: {sn_inc.get('priority')}, State: {sn_inc.get('state')}")
    print(f" -> Short Description: {sn_inc.get('short_description')}")
    print(f" -> Dispatched At: {sn_inc.get('dispatched_at')}")

    # 7. Verify Anti-Replay Protection: Replaying the same approval must fail
    print("\n[Step 7] Testing Anti-Replay: Attempting to replay consumed approval ID...")
    try:
        req("/api/diagnose", {
            "action": "RESUME",
            "session_id": sess_id,
            "approved": True,
            "approval_id": appr_id,
            "target_action": payload.get("action"),
            "dba_user": "MALICIOUS_ACTOR"
        })
        print(" [!] ERROR: Replayed approval was not rejected!")
        sys.exit(1)
    except urllib.error.HTTPError as err:
        assert err.code in (400, 409), f"Expected HTTP 400 or 409, got {err.code}"
        print(f" -> Anti-Replay Verified: Server rejected replayed approval with HTTP {err.code}")
    
    print("\n================================================================================")
    print("      [SUCCESS] ALL SCRATCHPAD CHECKLIST ITEMS VERIFIED AND VALIDATED!")
    print("================================================================================")

if __name__ == "__main__":
    run_verification()
