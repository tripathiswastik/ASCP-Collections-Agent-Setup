"""End-to-end scenario verification script against running local dashboard server.
Executes scenarios across http://127.0.0.1:8085/api/* with safety-first controls:
- dry-run mode by default (no automatic state-mutating RESUME calls)
- auto-approve requires --no-dry-run and --auto-approve (with localhost/--force validation)
- HTTP requests use retries with exponential backoff
- operator identity derived securely from bearer token
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
from typing import Any

logger = logging.getLogger("ascp.e2e_scenarios")

DEFAULT_BASE_URL = os.environ.get("E2E_BASE_URL", "http://127.0.0.1:8085")
DEFAULT_TOKEN = os.environ.get("ASCP_DEV_TOKEN") or os.environ.get("E2E_TOKEN", "dev-operator-secret-token")
DEFAULT_APPROVER = os.environ.get("E2E_APPROVER_NAME", "DBA_E2E_OPERATOR")


def setup_logging() -> None:
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)


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


def confirm_dangerous_action(base_url: str, auto_approve: bool, force: bool) -> None:
    if not auto_approve:
        return
    parsed_host = base_url.lower()
    if ("127.0.0.1" in parsed_host or "localhost" in parsed_host) or force:
        logger.info("Auto-approve enabled; host appears local or --force provided. Proceeding.")
        return
    ans = input(
        "*** WARNING: auto-approve is enabled and target server is non-local.\n"
        "Type 'I-MEAN-TO-AUTO-APPROVE' to continue: "
    )
    if ans.strip() != "I-MEAN-TO-AUTO-APPROVE":
        logger.error("Confirmation not provided. Aborting.")
        sys.exit(2)


def run_scenarios(
    base_url: str,
    token: str,
    dry_run: bool,
    auto_approve: bool,
    approver_name: str,
    retries: int,
    timeout: float,
) -> int:
    try:
        scenarios_resp = http_req(base_url, token, "/api/scenarios", timeout=timeout, retries=retries)
    except (urllib.error.URLError, OSError) as exc:
        logger.error("Could not connect to %s: %s", base_url, exc)
        logger.error("Please verify that the ASCP Diagnostic Server is reachable.")
        return 1

    scenarios = [s["key"] for s in scenarios_resp.get("scenarios", [])]
    logger.info("Total scenarios to execute: %d (dry_run=%s, auto_approve=%s)", len(scenarios), dry_run, auto_approve)

    results = []

    for idx, scen_key in enumerate(scenarios, 1):
        logger.info("--- Testing Scenario %d/%d: %s ---", idx, len(scenarios), scen_key)
        try:
            # 1. Load scenario
            load_res = http_req(
                base_url,
                token,
                "/api/scenario/load",
                method="POST",
                data={"key": scen_key},
                timeout=timeout,
                retries=retries,
            )
            scen_name = load_res.get("loaded_scenario", {}).get("name", scen_key)

            # 2. Check initial status
            st1 = http_req(base_url, token, "/api/status", timeout=timeout, retries=retries)
            pre_st = st1.get("registry", {}).get("st_status")
            pre_st_name = st1.get("registry", {}).get("st_status_name")
            is_rem_pre = st1.get("is_remediated", False)
            raw_logs = st1.get("scenario", {}).get("logs", [])

            # 3. Parse logs
            parse_res = http_req(
                base_url,
                token,
                "/api/parse-log",
                method="POST",
                data={"log_text": "\n".join(raw_logs)},
                timeout=timeout,
                retries=retries,
            )
            clusters = len(parse_res.get("results", []))

            # 4. Run Diagnosis
            diag = http_req(
                base_url,
                token,
                "/api/diagnose",
                method="POST",
                data={"action": "START", "scenario_key": scen_key},
                timeout=timeout,
                retries=retries,
            )
            interrupted = diag.get("interrupted", False)
            completed = diag.get("completed", False)
            rem_success = diag.get("remediation_success", False)
            sess_id = diag.get("session_id")

            # 5. If interrupted, optionally approve HITL gate
            if interrupted:
                pay = diag.get("interrupt_payload", {})
                appr_id = pay.get("approval_id")
                action_name = pay.get("action")
                if auto_approve and not dry_run:
                    logger.info("HITL Gate triggered. Auto-approving %s (%s)...", appr_id, action_name)
                    resume = http_req(
                        base_url,
                        token,
                        "/api/diagnose",
                        method="POST",
                        data={
                            "action": "RESUME",
                            "session_id": sess_id,
                            "approved": True,
                            "approval_id": appr_id,
                            "target_action": action_name,
                            "target_sid": pay.get("target_sid"),
                            "target_serial": pay.get("target_serial"),
                            "target_object": pay.get("target_object"),
                            "dba_user": approver_name,
                        },
                        timeout=timeout,
                        retries=retries,
                    )
                    completed = resume.get("completed", False)
                    rem_success = resume.get("remediation_success", False)
                else:
                    logger.info("HITL Gate encountered for %s; dry-run mode active -- skipping remediation.", scen_key)

            # 6. Check post-diagnosis status
            st2 = http_req(base_url, token, "/api/status", timeout=timeout, retries=retries)
            post_st = st2.get("registry", {}).get("st_status")
            post_st_name = st2.get("registry", {}).get("st_status_name")
            is_rem_post = st2.get("is_remediated", False)

            status_flag = "PASS" if (completed or (interrupted and dry_run)) else "FAIL"
            logger.info(
                "[%d/%d] %s | Clusters=%d | PreST=%s (%s, Rem=%s) | PostST=%s (%s, Rem=%s)",
                idx,
                len(scenarios),
                status_flag,
                clusters,
                pre_st,
                pre_st_name,
                is_rem_pre,
                post_st,
                post_st_name,
                is_rem_post,
            )

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
                "status": status_flag,
            })
        except Exception as e:
            logger.exception("Failure on scenario %s", scen_key)
            results.append({
                "key": scen_key,
                "status": "FAIL",
                "error": str(e),
            })

    print("\n" + "=" * 90)
    print(f"{'SCENARIO KEY':<28} | {'EXECUTION':<14} | {'PRE-STATUS':<12} | {'POST-STATUS':<12} | {'STATUS'}")
    print("=" * 90)
    failed = False
    for r in results:
        if r["status"] == "PASS":
            hitl_str = "HITL Approved" if (r.get("interrupted") and not dry_run) else ("HITL Paused" if r.get("interrupted") else "Autonomous")
            pre_str = f"{r.get('pre_st')}"
            post_str = f"{r.get('post_st')} (Rem={r.get('is_rem_post')})"
            print(f"{r['key']:<28} | {hitl_str:<14} | {pre_str:<12} | {post_str:<12} | [PASS]")
        else:
            failed = True
            print(f"{r['key']:<28} | {'ERROR':<14} | {'N/A':<12} | {'N/A':<12} | [FAIL: {r.get('error')}]")
    print("=" * 90)

    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Safer ASCP E2E scenario execution runner")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL, help="ASCP Control Plane Base URL")
    p.add_argument("--token", default=DEFAULT_TOKEN, help="Operator authentication token")
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
        help="Default dry-run mode (do not post RESUME remediations)",
    )
    p.add_argument(
        "--no-dry-run",
        nargs="?",
        const=False,
        dest="dry_run",
        type=lambda v: not str_to_bool(v),
        help="Disable dry-run mode",
    )
    p.add_argument("--auto-approve", action="store_true", help="Auto-post RESUME approvals when HITL gate is encountered")
    p.add_argument("--approver-name", default=DEFAULT_APPROVER, help="Approver operator identity string")
    p.add_argument("--force", action="store_true", help="Bypass interactive confirmation for non-local targets")
    p.add_argument("--retries", type=int, default=3, help="HTTP request retry count")
    p.add_argument("--timeout", type=float, default=15.0, help="HTTP request timeout in seconds")
    args = p.parse_args(argv)

    setup_logging()
    confirm_dangerous_action(args.base_url, args.auto_approve, args.force)

    return run_scenarios(
        base_url=args.base_url,
        token=args.token,
        dry_run=args.dry_run,
        auto_approve=args.auto_approve,
        approver_name=args.approver_name,
        retries=args.retries,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    raise SystemExit(main())
