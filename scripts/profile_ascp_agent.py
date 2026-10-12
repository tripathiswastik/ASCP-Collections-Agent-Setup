"""Profiling script for ASCP Collections Diagnostic Agent.
Runs cProfile and memory diagnostics across:
1. DrainLogParser (hot loop parsing & regex matching)
2. LockDiagnosticsEngine (hierarchical lock query & tree isolation)
3. CompiledStateGraph execution (full LangGraph super-step pipeline)
"""

import cProfile
import pstats
import io
import time
import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ascp_agent.drain_parser import DrainLogParser
from ascp_agent.lock_engine import LockDiagnosticsEngine
from ascp_agent.graph import create_ascp_diagnostic_graph
from ascp_agent.simulator import SCENARIOS

def benchmark_drain_parser(iterations=500):
    parser = DrainLogParser()
    sample_logs = SCENARIOS["ora_00054_mode6"]["logs"]
    for _ in range(iterations):
        for line in sample_logs:
            parser.parse_line(line)

def benchmark_lock_engine(iterations=200):
    engine = LockDiagnosticsEngine(simulated_scenario="ora_00054_mode6")
    for _ in range(iterations):
        telemetry = engine.execute_hierarchical_lock_query()
        engine.isolate_root_blocker(telemetry)

def benchmark_graph_execution(iterations=50):
    graph = create_ascp_diagnostic_graph()
    sample_logs = SCENARIOS["ora_00054_mode6"]["logs"]
    for i in range(iterations):
        state = graph.invoke(
            initial_state={"remediation_action": "INSPECT_LOCKS", "raw_logs": sample_logs},
            config={"configurable": {"thread_id": f"prof-thread-{i}"}}
        )

def run_cpu_profile():
    print("=" * 80)
    print("      RUNNING cProfile CPU PROFILING ON ASCP DIAGNOSTIC AGENT")
    print("=" * 80)
    pr = cProfile.Profile()
    pr.enable()

    t0 = time.perf_counter()
    benchmark_drain_parser(200)
    benchmark_lock_engine(100)
    benchmark_graph_execution(30)
    total_time = time.perf_counter() - t0

    pr.disable()
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats(pstats.SortKey.CUMULATIVE)
    ps.print_stats(30)

    print(f"\n[+] Total benchmark execution time: {total_time:.4f}s")
    print("\n[+] Top 30 Hotspot Functions by Cumulative Time:")
    print(s.getvalue())

if __name__ == "__main__":
    run_cpu_profile()
