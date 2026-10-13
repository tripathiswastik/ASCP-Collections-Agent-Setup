"""End-to-end scenario verification script against running local dashboard server.
Executes all scenarios across http://127.0.0.1:8085/api/*.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
import urllib.error
import urllib.request

TOKEN = os.environ.get("ASCP_DEV_TOKEN", "dev-operator-secret-token")


def req(url: str, method: str = "GET", data: dict | None = None) -> dict:
    headers = {"Authorization": f"Bearer {TOKEN}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(data).encode("utf-8")
    else:
        body = None
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(r) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    try:
        scenarios_resp = req("http://127.0.0.1:8085/api/scenarios")
    except (urllib.error.URLError, OSError) as exc:
        print(f"[-] Could not connect to http://127.0.0.1:8085: {exc}")
        print("    Please start the server first: python web/server.py 8085")
        return 1

    scenarios = [s["key"] for s in scenarios_resp["scenarios"]]
    print(f"Total scenarios to test: {len(scenarios)}")

    results = []

    for idx, scen_key in enumerate(scenarios, 1):
        print(f"\n--- Testing Scenario {idx}: {scen_key} ---")
        try:
            # 1. Load scenario
            load_res = req("http://127.0.0.1:8085/api/scenario/load", "POST", {"key": scen_key})
            scen_name = load_res["loaded_scenario"]["name"]
            print(f"Name: {scen_name}")

            # 2. Check initial status
            st1 = req("http://127.0.0.1:8085/api/status")
            pre_st = st1["registry"]["st_status"]
            pre_st_name = st1["registry"]["st_status_name"]
            is_rem_pre = st1["is_remediated"]
            print(f"Pre-diag ST_STATUS: {pre_st} ({pre_st_name}) | Remediated: {is_rem_pre}")

            # 3. Parse logs
            parse_res = req("http://127.0.0.1:8085/api/parse-log", "POST", {"log_text": "\n".join(st1["scenario"]["logs"])})
            clusters = len(parse_res.get("results", []))
            print(f"Log clusters: {clusters}")

            # 4. Run Diagnosis
            diag = req("http://127.0.0.1:8085/api/diagnose", "POST", {"action": "START", "scenario_key": scen_key})
            interrupted = diag.get("interrupted", False)
            completed = diag.get("completed", False)
            rem_success = diag.get("remediation_success", False)
            msg_count = len(diag.get("state", {}).get("messages", []))
            sess_id = diag.get("session_id")
            print(f"Diag: Interrupted={interrupted}, Completed={completed}, RemSuccess={rem_success}, Msgs={msg_count}")

            # 5. If interrupted, approve HITL gate
            if interrupted:
                pay = diag.get("interrupt_payload", {})
                appr_id = pay.get("approval_id")
                action_name = pay.get("action")
                print(f"HITL Gate triggered! Approving {appr_id} ({action_name})...")
                resume = req("http://127.0.0.1:8085/api/diagnose", "POST", {
                    "action": "RESUME",
                    "session_id": sess_id,
                    "approved": True,
                    "approval_id": appr_id,
                    "target_action": action_name,
                    "target_sid": pay.get("target_sid"),
                    "target_serial": pay.get("target_serial"),
                    "target_object": pay.get("target_object"),
                    "dba_user": "DBA_OPERATOR"
                })
                completed = resume.get("completed", False)
                rem_success = resume.get("remediation_success", False)
                print(f"Resumed Diag: Completed={completed}, RemSuccess={rem_success}")

            # 6. Check post-diagnosis status
            st2 = req("http://127.0.0.1:8085/api/status")
            post_st = st2["registry"]["st_status"]
            post_st_name = st2["registry"]["st_status_name"]
            is_rem_post = st2["is_remediated"]
            print(f"Post-diag ST_STATUS: {post_st} ({post_st_name}) | Remediated: {is_rem_post}")

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
                "status": "PASS"
            })
        except (urllib.error.URLError, json.JSONDecodeError, KeyError, AssertionError) as e:
            print(f"ERROR on {scen_key}: {e}")
            traceback.print_exc()
            results.append({
                "key": scen_key,
                "status": "FAIL",
                "error": str(e)
            })

    print("\n" + "=" * 90)
    print(f"{'SCENARIO KEY':<28} | {'EXECUTION':<14} | {'PRE-STATUS':<12} | {'POST-STATUS':<12} | {'STATUS'}")
    print("=" * 90)
    failed = False
    for r in results:
        if r["status"] == "PASS":
            hitl_str = "HITL Approved" if r["interrupted"] else "Autonomous"
            pre_str = f"{r['pre_st']}"
            post_str = f"{r['post_st']} (Rem={r['is_rem_post']})"
            print(f"{r['key']:<28} | {hitl_str:<14} | {pre_str:<12} | {post_str:<12} | [PASS]")
        else:
            failed = True
            print(f"{r['key']:<28} | {'ERROR':<14} | {'N/A':<12} | {'N/A':<12} | [FAIL: {r.get('error')}]")
    print("=" * 90)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
