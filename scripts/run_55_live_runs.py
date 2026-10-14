"""Safer ASCP Diagnostic Agent Live Execution Harness.
Replaces the original run_55_live_runs.py with safety-first behavior:
- default is dry-run (no RESUME approvals)
- auto-approve requires --auto-approve and --force (or running against localhost)
- configurable approver name and token via flags/env
- HTTP requests use retries with exponential backoff
- run records are persisted to a JSONL logfile for post-mortem
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

DEFAULT_BASE_URL = os.getenv("E2E_BASE_URL", "http://127.0.0.1:8085")
DEFAULT_TOKEN = os.getenv("E2E_TOKEN", "")
DEFAULT_APPROVER = os.getenv("E2E_APPROVER_NAME", "DBA_LIVE_RUNNER")

LOG_DIR = os.getenv("E2E_LOG_DIR", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("ascp.live_harness")


def setup_logging(log_file_path: str) -> None:
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    fh = logging.FileHandler(log_file_path, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)


def http_req(
    base_url: str,
    token: str,
    path: str,
    method: str = "GET",
    data: dict[str, Any] | None = None,
    timeout: float = 15.0,
    retries: int = 3,
    backoff_factor: float = 1.5,
) -> dict[str, Any]:
    """Perform HTTP request with simple retries and exponential backoff.
    Raises the last exception on final failure.
    """
    url = f"{base_url}{path}"
    body = json.dumps(data).encode("utf-8") if data is not None else None
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if data is not None:
        headers["Content-Type"] = "application/json"

    attempt = 0
    while True:
        attempt += 1
        try:
            if not url.startswith(("http://", "https://")):
                raise ValueError(f"Unsupported protocol scheme in {url}")
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as he:
            # HTTP errors are unlikely to succeed on retry for 4xx, but may for 5xx
            status = getattr(he, "code", None)
            if status and 500 <= status < 600 and attempt <= retries:
                sleep_for = backoff_factor ** (attempt - 1)
                logger.warning("HTTP 5xx on %s (attempt %d/%d). Backing off %.1fs...", url, attempt, retries, sleep_for)
                time.sleep(sleep_for)
                continue
            logger.error("HTTPError on %s: %s", url, he)
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt <= retries:
                sleep_for = backoff_factor ** (attempt - 1)
                logger.warning(
                    "Network error on %s (attempt %d/%d): %s -- retrying in %.1fs",
                    url,
                    attempt,
                    retries,
                    e,
                    sleep_for,
                )
                time.sleep(sleep_for)
                continue
            logger.error("Network failure on %s after %d attempts: %s", url, attempt - 1, e)
            raise


def persist_record(log_path: str, record: dict[str, Any]) -> None:
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def confirm_dangerous_action(base_url: str, auto_approve: bool, force: bool) -> None:
    if not auto_approve:
        return
    # If auto-approve and not forced, require user confirmation unless running against localhost
    parsed_host = base_url.lower()
    if ("127.0.0.1" in parsed_host or "localhost" in parsed_host) or force:
        logger.info("Auto-approve enabled; host appears local or --force provided. Proceeding.")
        return
    # Otherwise prompt
    ans = input(
        "*** WARNING: auto-approve is enabled and target server is non-local. "
        "This may trigger destructive remediation actions.\n"
        "Type 'I-MEAN-TO-AUTO-APPROVE' to continue: "
    )
    if ans.strip() != "I-MEAN-TO-AUTO-APPROVE":
        logger.error("Confirmation not provided. Aborting.")
        sys.exit(2)


def run_live_runs(
    base_url: str,
    token: str,
    count: int,
    dry_run: bool,
    auto_approve: bool,
    approver_name: str,
    retries: int,
    timeout: float,
    log_file: str,
) -> dict[str, Any]:
    start_time = time.time()
    logger.info("Starting live-run harness (count=%d, dry_run=%s, auto_approve=%s)", count, dry_run, auto_approve)

    # Fetch scenarios
    scenarios_resp = http_req(base_url, token, "/api/scenarios", timeout=timeout, retries=retries)
    scenario_list = scenarios_resp.get("scenarios", [])
    if not scenario_list:
        logger.error("No scenarios returned from %s/api/scenarios", base_url)
        raise RuntimeError("No failure scenarios available from server API.")

    scenarios = [s["key"] for s in scenario_list]
    num_scenarios = len(scenarios)
    rounds = (count + num_scenarios - 1) // num_scenarios
    logger.info("Loaded %d scenarios; planning %d round(s) to reach %d runs.", num_scenarios, rounds, count)

    run_count = 0
    success_count = 0
    hitl_approvals = 0
    records = []

    for round_idx in range(1, rounds + 1):
        logger.info("Starting round %d/%d", round_idx, rounds)
        for scen_key in scenarios:
            if run_count >= count:
                break
            run_count += 1
            run_start = time.time()
            now_iso = datetime.now(timezone.utc).isoformat()
            rec: dict[str, Any] = {
                "run_id": run_count,
                "round": round_idx,
                "scenario_key": scen_key,
                "timestamp": now_iso,
            }
            try:
                # 1) Load scenario
                load_res = http_req(
                    base_url,
                    token,
                    "/api/scenario/load",
                    method="POST",
                    data={"key": scen_key},
                    timeout=timeout,
                    retries=retries,
                )
                rec["scenario_name"] = load_res.get("loaded_scenario", {}).get("name", scen_key)

                # 2) Status
                st = http_req(base_url, token, "/api/status", timeout=timeout, retries=retries)
                raw_logs = st.get("scenario", {}).get("logs", [])

                # 3) Parse logs
                parse_res = http_req(
                    base_url,
                    token,
                    "/api/parse-log",
                    method="POST",
                    data={"log_text": "\n".join(raw_logs)},
                    timeout=timeout,
                    retries=retries,
                )
                parsed_clusters = len(parse_res.get("results", []))
                rec["parsed_clusters"] = parsed_clusters

                # 4) Diagnose START
                diag = http_req(
                    base_url,
                    token,
                    "/api/diagnose",
                    method="POST",
                    data={"action": "START", "scenario_key": scen_key},
                    timeout=timeout,
                    retries=retries,
                )
                sess_id = diag.get("session_id")
                interrupted = diag.get("interrupted", False)
                completed = diag.get("completed", False)
                rec.update({"session_id": sess_id, "interrupted": interrupted, "completed": completed})

                # 5) Optionally RESUME if interrupted (only when auto_approve and not dry-run)
                if interrupted:
                    rec["interrupt_payload"] = diag.get("interrupt_payload", {})
                    if auto_approve and not dry_run:
                        hitl_approvals += 1
                        payload = diag.get("interrupt_payload", {})
                        resume_payload = {
                            "action": "RESUME",
                            "session_id": sess_id,
                            "approved": True,
                            "approval_id": payload.get("approval_id"),
                            "target_action": payload.get("action"),
                            "target_sid": payload.get("target_sid"),
                            "target_serial": payload.get("target_serial"),
                            "target_object": payload.get("target_object"),
                            "dba_user": approver_name,
                        }
                        logger.info("Auto-approving HITL for session %s (scenario=%s)", sess_id, scen_key)
                        resume = http_req(
                            base_url,
                            token,
                            "/api/diagnose",
                            method="POST",
                            data=resume_payload,
                            timeout=timeout,
                            retries=retries,
                        )
                        completed = resume.get("completed", completed)
                        rec["resume_completed"] = completed
                    else:
                        logger.info(
                            "HITL encountered for run %d; dry_run=%s auto_approve=%s -- not resuming",
                            run_count,
                            dry_run,
                            auto_approve,
                        )

                # 6) Post-diagnosis check
                post_st = http_req(base_url, token, "/api/status", timeout=timeout, retries=retries)
                pipeline_remediated = post_st.get("is_remediated", False)
                rec["pipeline_remediated"] = pipeline_remediated

                elapsed_ms = round((time.time() - run_start) * 1000, 1)
                rec["elapsed_ms"] = elapsed_ms
                rec["status"] = "PASS" if completed else "FAIL"
                if completed:
                    success_count += 1

                logger.info(
                    "[%d/%d] %s | %6.1fms | Clusters=%d | HITL=%s | Remediated=%s | %s",
                    run_count,
                    count,
                    rec["status"],
                    elapsed_ms,
                    parsed_clusters,
                    str(interrupted),
                    str(pipeline_remediated),
                    scen_key,
                )

            except Exception as e:
                elapsed_ms = round((time.time() - run_start) * 1000, 1)
                logger.exception("Run %d failed for scenario %s", run_count, scen_key)
                rec.update({"status": "ERROR", "error": str(e), "elapsed_ms": elapsed_ms})

            # persist per-run record
            persist_record(log_file, rec)
            records.append(rec)

    total_duration = time.time() - start_time
    avg_latency = sum(r.get("elapsed_ms", 0.0) for r in records) / len(records) if records else 0.0
    success_rate = (success_count / run_count * 100.0) if run_count > 0 else 0.0

    summary = {
        "total_runs": run_count,
        "success_count": success_count,
        "success_rate_pct": round(success_rate, 1),
        "hitl_approvals": hitl_approvals,
        "avg_latency_ms": round(avg_latency, 1),
        "total_time_s": round(total_duration, 2),
    }
    logger.info("HARNESS SUMMARY: %s", json.dumps(summary))
    return {"summary": summary, "records": records}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Safer ASCP live-run harness")
    p.add_argument("-c", "--count", type=int, default=5, help="Number of runs to execute (default: 5 for safety)")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Control plane base URL")
    p.add_argument("--token", default=DEFAULT_TOKEN, help="Operator API token (or set E2E_TOKEN)")
    def str_to_bool(val: Any) -> bool:
        if isinstance(val, bool):
            return val
        return str(val).lower() in ("true", "1", "yes", "y", "t")

    p.add_argument(
        "--dry-run",
        nargs="?",
        const=True,
        default=True,
        type=str_to_bool,
        help="Dry run mode (do not post RESUME approvals)",
    )
    p.add_argument(
        "--no-dry-run",
        nargs="?",
        const=False,
        dest="dry_run",
        type=lambda v: not str_to_bool(v),
        help="Disable dry run mode",
    )
    p.add_argument("--auto-approve", action="store_true", help="If set (and not dry-run), auto-post RESUME approvals when HITL is encountered")
    p.add_argument("--approver-name", default=DEFAULT_APPROVER, help="Name to include in approval payload (dba_user)")
    p.add_argument("--retries", type=int, default=3, help="Per-request retry count")
    p.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout seconds")
    p.add_argument("--log-file", default=os.path.join(LOG_DIR, f"run_55_live_runs_{int(time.time())}.jsonl"), help="JSONL output log file")
    p.add_argument("--force", action="store_true", help="Skip interactive confirmation when enabling auto-approve (use with caution)")
    args = p.parse_args(argv)

    # Setup logging
    setup_logging(args.log_file + ".log")
    logger.info("Harness starting; log file=%s", args.log_file)

    if not args.token:
        logger.error("No API token provided. Pass --token or export E2E_TOKEN environment variable.")
        return 2

    # Confirm if auto-approve requested
    confirm_dangerous_action(args.base_url, args.auto_approve, args.force)

    try:
        result = run_live_runs(
            base_url=args.base_url,
            token=args.token,
            count=args.count,
            dry_run=args.dry_run,
            auto_approve=args.auto_approve,
            approver_name=args.approver_name,
            retries=args.retries,
            timeout=args.timeout,
            log_file=args.log_file,
        )
        # write summary file for convenience
        summary_path = args.log_file + ".summary.json"
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump(result["summary"], fh, indent=2)
        logger.info("Summary written to %s", summary_path)
        # Exit code: 0 if all requested runs completed successfully, 1 otherwise
        total = result["summary"]["total_runs"]
        success = result["summary"]["success_count"]
        return 0 if success == total else 1
    except Exception:
        logger.exception("Harness failed")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
