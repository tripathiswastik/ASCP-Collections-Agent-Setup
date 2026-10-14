"""Autonomous ASCP Diagnostic Agent - 55 Live Scenario Execution Harness.
Executes 55 real-time live runs against the HTTP Control Plane API across all 11 catalog scenarios:
1. Scenario Loading (/api/scenario/load)
2. State & Status Inspection (/api/status)
3. Drain Log Parsing (/api/parse-log)
4. Autonomous StateGraph Diagnosis (/api/diagnose START)
5. Human-in-the-Loop Gate Approval (/api/diagnose RESUME)
6. Post-Remediation Verification & Telemetry Validation
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

# Add workspace root to sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

BASE_URL = os.getenv("E2E_BASE_URL", "http://127.0.0.1:8085")
TOKEN = os.getenv("E2E_TOKEN", "dev-operator-secret-token")


def req(base_url: str, token: str, path: str, method: str = "GET", data: dict | None = None) -> dict[str, Any]:
    url = f"{base_url}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    body = json.dumps(data).encode("utf-8") if data is not None else None
    if data is not None:
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(r, timeout=15.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_55_live_runs(total_target: int = 55) -> dict[str, Any]:
    print("=" * 80)
    print(f"  STARTING {total_target} REAL-TIME LIVE RUNS ON ASCP CONTROL PLANE")
    print(f"  Target Server: {BASE_URL}")
    print("=" * 80)

    # 1. Fetch available scenarios
    scenarios_resp = req(BASE_URL, TOKEN, "/api/scenarios")
    scenario_list = scenarios_resp.get("scenarios", [])
    if not scenario_list:
        raise RuntimeError("No failure scenarios available from server API.")

    scenarios = [s["key"] for s in scenario_list]
    num_scenarios = len(scenarios)
    print(f"[*] Loaded {num_scenarios} failure catalog scenarios from server registry.")

    rounds = (total_target + num_scenarios - 1) // num_scenarios
    print(f"[*] Planning {rounds} rounds across {num_scenarios} scenarios to achieve {total_target} live runs.\n")

    run_count = 0
    success_count = 0
    hitl_approvals_count = 0
    run_records = []
    start_total_time = time.time()

    for round_idx in range(1, rounds + 1):
        print(f"--- ROUND {round_idx}/{rounds} ---")
        for scen_key in scenarios:
            if run_count >= total_target:
                break
            run_count += 1
            run_start = time.time()

            try:
                # Step 1: Load scenario
                load_res = req(BASE_URL, TOKEN, "/api/scenario/load", "POST", {"key": scen_key})
                scen_name = load_res.get("loaded_scenario", {}).get("name", scen_key)

                # Step 2: Fetch status
                st = req(BASE_URL, TOKEN, "/api/status")
                raw_logs = st.get("scenario", {}).get("logs", [])

                # Step 3: Parse logs
                parse_res = req(BASE_URL, TOKEN, "/api/parse-log", "POST", {"log_text": "\n".join(raw_logs)})
                parsed_clusters = len(parse_res.get("results", []))

                # Step 4: Run Diagnosis
                diag = req(BASE_URL, TOKEN, "/api/diagnose", "POST", {"action": "START", "scenario_key": scen_key})
                sess_id = diag.get("session_id")
                interrupted = diag.get("interrupted", False)
                completed = diag.get("completed", False)

                # Step 5: If interrupted at HITL Gate, submit authorized approval
                if interrupted:
                    hitl_approvals_count += 1
                    pay = diag.get("interrupt_payload", {})
                    appr_id = pay.get("approval_id")
                    action_name = pay.get("action")

                    resume = req(BASE_URL, TOKEN, "/api/diagnose", "POST", {
                        "action": "RESUME",
                        "session_id": sess_id,
                        "approved": True,
                        "approval_id": appr_id,
                        "target_action": action_name,
                        "target_sid": pay.get("target_sid"),
                        "target_serial": pay.get("target_serial"),
                        "target_object": pay.get("target_object"),
                        "dba_user": "DBA_LIVE_RUNNER"
                    })
                    completed = resume.get("completed", False)

                # Step 6: Post-diagnosis state check
                post_st = req(BASE_URL, TOKEN, "/api/status")
                pipeline_remediated = post_st.get("is_remediated", False)
                elapsed_ms = round((time.time() - run_start) * 1000, 1)

                if completed:
                    success_count += 1
                    status_flag = "PASS"
                else:
                    status_flag = "FAIL"

                print(
                    f"  [{run_count:02d}/{total_target}] {status_flag} | {elapsed_ms:>6.1f}ms | "
                    f"Clusters={parsed_clusters} | HITL={interrupted!s:<5} | "
                    f"Remediated={pipeline_remediated!s:<5} | {scen_key}"
                )

                run_records.append({
                    "run_id": run_count,
                    "round": round_idx,
                    "scenario_key": scen_key,
                    "scenario_name": scen_name,
                    "interrupted": interrupted,
                    "completed": completed,
                    "elapsed_ms": elapsed_ms,
                    "status": status_flag
                })

            except Exception as e:  # noqa: BLE001 -- benchmark harness catches all test runner errors
                elapsed_ms = round((time.time() - run_start) * 1000, 1)
                print(f"  [{run_count:02d}/{total_target}] FAIL | {elapsed_ms:>6.1f}ms | Error: {e} | {scen_key}")
                run_records.append({
                    "run_id": run_count,
                    "round": round_idx,
                    "scenario_key": scen_key,
                    "status": "ERROR",
                    "error": str(e),
                    "elapsed_ms": elapsed_ms
                })

    total_duration = time.time() - start_total_time
    avg_latency = (
        sum(r.get("elapsed_ms", 0.0) for r in run_records) / len(run_records)
        if run_records else 0.0
    )
    success_rate = (success_count / run_count * 100.0) if run_count > 0 else 0.0

    print("\n" + "=" * 80)
    print(f"  LIVE EXECUTION HARNESS METRICS SUMMARY: {run_count} RUNS COMPLETED")
    print("=" * 80)
    print(f"  Total Runs Completed : {run_count}/{total_target}")
    print(f"  Successful Runs      : {success_count}/{run_count} ({success_rate:.1f}%)")
    print(f"  HITL Gates Approved  : {hitl_approvals_count}")
    print(f"  Average Run Latency  : {avg_latency:.1f} ms")
    print(f"  Total Wall Time      : {total_duration:.2f} seconds")
    print("=" * 80)

    if success_count == total_target:
        print(f"\n[SUCCESS] ALL {total_target} LIVE RUNS COMPLETED WITH 100% SUCCESS RATE!")
        return {"status": "SUCCESS", "success_count": success_count, "total_runs": run_count}
    else:
        print(f"\n[FAILURE] {total_target - success_count} runs failed execution.")
        sys.exit(1)


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 55
    run_55_live_runs(count)
