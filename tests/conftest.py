"""
Python Version: 3.10+ (Target: Python 3.10, 3.11, 3.12)
Purpose: Centralized test fixtures, telemetry mocks, and database connection factories for ASCP Diagnostic Agent test suite.
Runs-in: Pytest and unittest execution harnesses across local and CI environments.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

# Ensure repository root is on sys.path for pytest collection
REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Reusable Raw Log Fixture
SAMPLE_ORA00054_LOGS: list[str] = [
    "+---------------------------------------------------------------------------+",
    "Planning Data Collection Centralized Architecture Worker (MSCPDCW)",
    "Current system time is 12-OCT-2025 04:12:00",
    "+---------------------------------------------------------------------------+",
    "[12-OCT-2025 04:12:01]: Launching Planning ODS Load Worker 1 (MSCPDCW)",
    "[12-OCT-2025 04:12:03]: Attempting partition exchange on target table MSC_ST_DEMANDS.",
    "[12-OCT-2025 04:12:05]: Cause: ORA-00054: resource busy and acquire with NOWAIT specified on table MSC_ST_DEMANDS.",
    "[12-OCT-2025 04:12:06]: Action: Contact DBA to verify blocking locks on staging tables.",
    "[12-OCT-2025 04:12:10]: Worker process 31902 terminated with fatal error status.",
    "+---------------------------------------------------------------------------+"
]

# Reusable Root Blocker & Lock Telemetry Fixture
SAMPLE_LOCK_TELEMETRY: list[dict[str, Any]] = [
    {
        "lock_depth": 1,
        "is_blocked_leaf": 0,
        "sid": 412,
        "serial_number": 28419,
        "oracle_username": "APPS",
        "os_user_name": "applmgr",
        "os_process_id": "28419",
        "module": "SQL*Plus",
        "action": "MANUAL_MAINTENANCE",
        "blocking_session": None,
        "object_id": 89234,
        "object_name": "MSC_ST_DEMANDS",
        "locked_mode": 6,
        "locked_mode_text": "Exclusive (X)",
        "operational_impact": "Exclusive Table Lock. Completely blocks MSCPDCP staging truncations and parallel worker writes.",
        "current_sql_text": "LOCK TABLE MSC_ST_DEMANDS IN EXCLUSIVE MODE NOWAIT"
    },
    {
        "lock_depth": 2,
        "is_blocked_leaf": 1,
        "sid": 528,
        "serial_number": 19204,
        "oracle_username": "APPS",
        "os_user_name": "applmgr",
        "os_process_id": "19204",
        "module": "MSCPDCW",
        "action": "ODS_LOAD_DEMANDS_WORKER_1",
        "blocking_session": 412,
        "object_id": 89234,
        "object_name": "MSC_ST_DEMANDS",
        "locked_mode": 0,
        "locked_mode_text": "NONE",
        "operational_impact": "Lock requested but not yet obtained. Worker queued waiting on target table.",
        "current_sql_text": "INSERT /*+ APPEND */ INTO MSC_DEMANDS (PLAN_ID, ...) SELECT -1, ... FROM MSC_ST_DEMANDS"
    }
]

SAMPLE_ROOT_BLOCKER: dict[str, Any] = SAMPLE_LOCK_TELEMETRY[0]

# Reusable Diagnostic State Fixture
SAMPLE_AGENT_STATE: dict[str, Any] = {
    "remediation_action": "KILL_SESSION",
    "failure_domain": "DATABASE_LOCK",
    "confidence_score": 96.5,
    "risk_level": "HIGH",
    "lock_telemetry": SAMPLE_LOCK_TELEMETRY,
    "context": {
        "target_staging_table": "MSC_ST_DEMANDS",
        "failed_phase": "LOAD",
        "instance_id": 1001
    },
    "messages": []
}

def create_mock_db_cursor(rows: list[tuple] | None = None, description: list[tuple] | None = None):
    """Create a mock database cursor with configurable fetchall rows and column description."""
    cursor = MagicMock()
    cursor.description = description or [("sid",), ("serial#",), ("locked_mode",), ("object_name",)]
    cursor.fetchall.return_value = rows or [(412, 28419, 6, "MSC_ST_DEMANDS")]
    return cursor

def create_mock_db_connection(cursor: MagicMock | None = None):
    """Create a mock database connection returning a configured cursor."""
    conn = MagicMock()
    conn.cursor.return_value = cursor or create_mock_db_cursor()
    return conn

# Pytest fixtures if pytest is used
try:
    import pytest

    @pytest.fixture
    def mock_db_cursor():
        return create_mock_db_cursor()

    @pytest.fixture
    def mock_db_conn():
        return create_mock_db_connection()

    @pytest.fixture
    def sample_logs():
        return list(SAMPLE_ORA00054_LOGS)

    @pytest.fixture
    def lock_telemetry():
        return list(SAMPLE_LOCK_TELEMETRY)

    @pytest.fixture
    def root_blocker():
        return dict(SAMPLE_ROOT_BLOCKER)

    @pytest.fixture
    def agent_state():
        return dict(SAMPLE_AGENT_STATE)

    @pytest.fixture(autouse=True)
    def force_offline_mode(monkeypatch):
        """Guarantees unit tests execute in offline simulation mode without accidental live DB calls or audit file pollution."""
        monkeypatch.setenv("ASCP_PERSIST_AUDIT_LOG", "false")
        if os.getenv("RUN_REAL_ORACLE", "false").lower() != "true":
            monkeypatch.setenv("DISABLE_EXTERNAL_CALLS", "1")
            monkeypatch.setenv("FORCE_SIMULATION_MODE", "1")
        yield

except ImportError:
    pass
