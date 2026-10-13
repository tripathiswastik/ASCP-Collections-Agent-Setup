"""Command-Line Interface (CLI) for Autonomous ASCP Collections Diagnostic Agent.
Provides interactive triage commands for DBAs and automation pipelines.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from ascp_agent.drain_parser import DrainLogParser
from ascp_agent.graph import create_ascp_diagnostic_graph
from ascp_agent.lock_engine import LockDiagnosticsEngine
from ascp_agent.simulator import SCENARIOS
from ascp_agent.state import Command


def print_banner():
    banner = """
================================================================================
       AUTONOMOUS ASCP COLLECTIONS DIAGNOSTIC AGENT - ORACLE EBS & APS
================================================================================
    """
    print(banner)

def cmd_parse_log(args):
    """Parse log file using Drain fixed-depth tree algorithm."""
    filepath = args.file
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)

    parser = DrainLogParser()
    results = parser.parse_file(filepath)

    print(f"\n[+] Parsed {len(results)} lines using Drain Algorithm:")
    print("-" * 80)
    for res in results:
        print(f"Template ID #{res['cluster_id']}: {res['template']}")
        if res["parameters"]:
            print(f"   Parameters: {json.dumps(res['parameters'])}")
    print("-" * 80)

def cmd_locks(args):
    """Run real-time hierarchical lock diagnostics."""
    engine = LockDiagnosticsEngine(simulated_scenario=args.scenario)
    telemetry = engine.execute_hierarchical_lock_query()

    print("\n[+] Executing Hierarchical Root Blocker Query (CONNECT BY PRIOR):")
    print("=" * 80)
    if not telemetry:
        print("    No active blocking locks found across MSC_ST_* staging structures.")
        return

    for item in telemetry:
        indent = "  " * (item["lock_depth"] - 1)
        role = "[ROOT BLOCKER]" if item["lock_depth"] == 1 else "[BLOCKED WORKER]"
        print(f"{indent}{role} Depth: {item['lock_depth']} | SID: {item['sid']} (SERIAL# {item['serial_number']}) | User: {item['oracle_username']}")
        print(f"{indent}  Object: {item['object_name']} | Lock Mode: {item['locked_mode']} ({item['locked_mode_text']})")
        print(f"{indent}  Module: {item['module']} | Action: {item['action']}")
        print(f"{indent}  SQL: {item['current_sql_text']}")
        print(f"{indent}  Impact: {item['operational_impact']}")
        print("-" * 80)

def cmd_diagnose(args):
    """Execute end-to-end LangGraph state machine with HITL approval gate."""
    print(f"\n[+] Initializing ASCP Diagnostic StateGraph for scenario: {args.scenario}")
    graph = create_ascp_diagnostic_graph()

    # Step 1: Run graph until completion or HITL Interrupt Gate
    state = graph.invoke(
        initial_state={"remediation_action": "INSPECT_LOCKS"},
        config={"configurable": {"thread_id": f"cli-run-{args.scenario}"}}
    )

    print("\n--- Agent Execution Trace ---")
    for msg in state.get("messages", []):
        content = getattr(msg, "content", str(msg))
        role = getattr(msg, "role", "agent")
        print(f"[{role.upper()}]: {content}")

    # Step 2: Handle Human-in-the-Loop Interrupt Gate
    if state.get("interrupted"):
        interrupt_payload = state.get("interrupt_payload", {})
        conf = state.get("confidence_score", 0.0)
        domain = state.get("failure_domain", "UNKNOWN")
        print("\n" + "=" * 80)
        print("          HUMAN-IN-THE-LOOP (HITL) MANDATORY GOVERNANCE GATE")
        print("=" * 80)
        print(f"Failure Domain: {domain}")
        print(f"RCA Confidence: {conf:.1f}% (Threshold: 85.0%)")
        print(f"Target Action : {interrupt_payload.get('action')}")
        print(f"Risk Tier     : {interrupt_payload.get('risk_tier')}")
        print(f"Target Object : {interrupt_payload.get('target_object')}")
        print(f"Target Session: SID {interrupt_payload.get('target_sid')} (SERIAL# {interrupt_payload.get('target_serial')})")
        print(f"Recommended SQL: {interrupt_payload.get('recommended_sql')}")
        print(f"Reasoning     : {interrupt_payload.get('reasoning')}")
        print("=" * 80)

        if args.auto_approve:
            approved = True
            print("\n[+] --auto-approve flag detected. Proceeding with execution.")
        else:
            choice = input("\nApprove remediation execution? [y/N]: ").strip().lower()
            approved = choice in ["y", "yes"]

        # Resume state graph with human command
        resume_cmd = Command(resume={"approved": approved, "dba_user": "OPERATOR"})
        final_state = graph.invoke(
            config={"configurable": {"thread_id": f"cli-run-{args.scenario}"}},
            resume_command=resume_cmd
        )

        print("\n--- Final Execution Result ---")
        for msg in final_state.get("messages", [])[-2:]:
            content = getattr(msg, "content", str(msg))
            print(f"[REMEDIATION]: {content}")

        if final_state.get("servicenow_incident"):
            inc = final_state["servicenow_incident"]
            print(f"\n[+] ServiceNow Incident Dispatched: {inc.get('incident_number')} (SysID: {inc.get('sys_id')})")

        if final_state.get("recovery_command"):
            print("\n[+] Automated Staging Recovery Command (ST_STATUS Reset):")
            print(final_state["recovery_command"])

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Autonomous ASCP Collections Diagnostic Agent")
    subparsers = parser.add_subparsers(dest="command")

    # locks command
    p_locks = subparsers.add_parser("locks", help="Interrogate database dynamic views for locks")
    p_locks.add_argument("--scenario", default="ora_00054_mode6", choices=list(SCENARIOS.keys()))

    # parse-log command
    p_log = subparsers.add_parser("parse-log", help="Parse log file with Drain algorithm")
    p_log.add_argument("--file", required=True, help="Path to concurrent log file")

    # diagnose command
    p_diag = subparsers.add_parser("diagnose", help="Execute autonomous diagnostic state graph")
    p_diag.add_argument("--scenario", default="ora_00054_mode6", choices=list(SCENARIOS.keys()))
    p_diag.add_argument("--auto-approve", action="store_true", help="Automatically approve HITL gates")

    args = parser.parse_args()
    if args.command == "locks":
        cmd_locks(args)
    elif args.command == "parse-log":
        cmd_parse_log(args)
    elif args.command == "diagnose":
        cmd_diagnose(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
