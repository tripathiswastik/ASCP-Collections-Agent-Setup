"""Timeline-Based Incident Correlation Engine for Oracle ASCP.
Correlates planning-run IDs, concurrent request IDs, timestamps, session waits,
and collection jobs into a single unified incident timeline.

Normalizes timestamps to UTC while preserving the original time zone, and reconstructs
causal sequences to cleanly distinguish initiating root triggers from cascading downstream symptoms.
"""

from __future__ import annotations

import datetime
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Common EBS Log timestamp regexes:
# E.g. "[12-OCT-2025 04:12:01]" or "2025-10-12T04:12:01Z" or "12-OCT-2025 04:12:01 EDT"
_TIMESTAMP_PATTERN = re.compile(
    r"\[?(\d{1,2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\s+[A-Za-z]{3,4})?)\]?"
)
_ISO_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

MONTH_MAP = {
    "JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
    "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12
}


@dataclass
class TimelineEvent:
    """Normalized incident event on the master timeline."""
    event_id: str
    timestamp_utc: str  # ISO 8601 UTC representation
    timestamp_unix: float
    original_timestamp: str  # Exact string from log or Oracle view
    original_tz: str  # Original time zone (e.g., UTC, EDT, LOCAL)
    source: str  # LOG_EVENT, CONCURRENT_REQUEST, SESSION_WAIT, COLLECTION_JOB, PLANNING_RUN
    event_type: str  # STAGE_START, LOCK_HOLD, ERROR, CRASH, TIMEOUT, COMPLETION
    entity_id: str  # E.g., "SID_412", "REQ_9841203", "MSCPDCW_1", "PLAN_1001"
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    is_causal_trigger: bool = False  # Flagged if isolated as the initial upstream anomaly

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_and_normalize_timestamp(ts_str: str, default_tz: str = "UTC") -> tuple[str, float, str]:
    """Parses arbitrary EBS/Oracle timestamp string, returning (iso_utc, unix_sec, original_tz)."""
    clean = ts_str.strip().strip("[]")

    # Match EBS style: 12-OCT-2025 04:12:01 [EDT]
    match = re.match(r"^(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})(?:\s+([A-Za-z]{3,4}))?$", clean)
    if match:
        day, mon_str, year, hr, mi, sec, tz_abbr = match.groups()
        mon = MONTH_MAP.get(mon_str.upper(), 1)
        tz_name = tz_abbr or default_tz

        # Simple offset mapping for standard EBS server zones
        offset_hours = 0
        if tz_name.upper() in ("EDT", "EST"):
            offset_hours = -4 if tz_name.upper() == "EDT" else -5
        elif tz_name.upper() in ("CDT", "CST"):
            offset_hours = -5 if tz_name.upper() == "CDT" else -6
        elif tz_name.upper() in ("PDT", "PST"):
            offset_hours = -7 if tz_name.upper() == "PDT" else -8

        tz = datetime.timezone(datetime.timedelta(hours=offset_hours))
        dt = datetime.datetime(int(year), mon, int(day), int(hr), int(mi), int(sec), tzinfo=tz)
        dt_utc = dt.astimezone(datetime.timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"), dt_utc.timestamp(), tz_name

    # Try ISO-8601 parsing
    try:
        dt = datetime.datetime.fromisoformat(clean.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        dt_utc = dt.astimezone(datetime.timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"), dt_utc.timestamp(), "UTC"
    except (ValueError, TypeError, OverflowError):
        logger.debug("Could not parse timestamp %s as ISO-8601; using fallback.", clean)

    # Fallback to current UTC time if unparseable
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ"), now.timestamp(), default_tz


class IncidentTimelineEngine:
    """Ingests multi-source ASCP telemetry and correlates into an ordered causal timeline."""

    def __init__(self, incident_id: str | None = None):
        self.incident_id = incident_id or f"INC-{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}"
        self.events: list[TimelineEvent] = []

    def add_event(
        self,
        original_timestamp: str,
        source: str,
        event_type: str,
        entity_id: str,
        summary: str,
        details: dict[str, Any] | None = None,
        default_tz: str = "UTC",
    ) -> TimelineEvent:
        """Adds and normalizes an event into the timeline."""
        iso_utc, unix_ts, tz_name = parse_and_normalize_timestamp(original_timestamp, default_tz)
        event_id = f"EVT-{len(self.events) + 1:03d}"
        evt = TimelineEvent(
            event_id=event_id,
            timestamp_utc=iso_utc,
            timestamp_unix=unix_ts,
            original_timestamp=original_timestamp,
            original_tz=tz_name,
            source=source,
            event_type=event_type,
            entity_id=entity_id,
            summary=summary,
            details=details or {},
        )
        self.events.append(evt)
        return evt

    def ingest_logs(self, logs: list[str]) -> None:
        """Parses log lines, extracts timestamps, detects key milestones and errors."""
        for line in logs:
            if not line.strip():
                continue
            ts_match = _TIMESTAMP_PATTERN.search(line) or _ISO_PATTERN.search(line)
            ts_str = ts_match.group(1) if ts_match else "01-JAN-2025 00:00:00 UTC"

            # Determine event characteristics
            line_upper = line.upper()
            if "ORA-" in line_upper or "ERROR" in line_upper or "FATAL" in line_upper or "ABORT" in line_upper:
                ev_type = "ERROR"
            elif "LAUNCHING" in line_upper or "BEGINNING" in line_upper or "SPAWNING" in line_upper:
                ev_type = "STAGE_START"
            elif "COMPLETED" in line_upper:
                ev_type = "COMPLETION"
            else:
                ev_type = "INFO"

            # Entity identification
            entity = "ASCP_ENGINE"
            if "MSCPDCW" in line_upper or "WORKER" in line_upper:
                w_match = re.search(r"Worker\s+(\d+)", line, re.IGNORECASE)
                entity = f"WORKER_{w_match.group(1)}" if w_match else "WORKER_ODS"
            elif "MSCPDP" in line_upper:
                entity = "MSCPDP_PULL"
            elif "MSRFWOR" in line_upper:
                entity = "MSRFWOR_SNAPSHOT"
            elif "MSCPDCP" in line_upper:
                entity = "MSCPDCP_PURGE"

            self.add_event(
                original_timestamp=ts_str,
                source="LOG_EVENT",
                event_type=ev_type,
                entity_id=entity,
                summary=line.strip(),
                details={"raw_log_line": line},
            )

    def ingest_session_waits(self, waits: list[dict[str, Any]], timestamp_str: str | None = None) -> None:
        """Ingests database session lock and wait telemetry into the incident timeline."""
        ts = timestamp_str or datetime.datetime.now(datetime.timezone.utc).isoformat()
        for w in waits:
            sid = w.get("sid", 0)
            bsid = w.get("blocking_session")
            obj = w.get("object_name", "DATABASE_OBJECT")
            event_name = w.get("event", "enq: TM - contention")
            sql = w.get("sql_text", "")

            if bsid:
                summary = f"Session SID {sid} blocked waiting on {event_name} (blocked by SID {bsid}) on {obj}"
                ev_type = "LOCK_WAIT"
            else:
                summary = f"Session SID {sid} holding lock on {obj} (event: {event_name}, sql: {sql})"
                ev_type = "LOCK_HOLD"

            self.add_event(
                original_timestamp=ts,
                source="SESSION_WAIT",
                event_type=ev_type,
                entity_id=f"SID_{sid}",
                summary=summary,
                details=w,
            )

    def ingest_concurrent_request(self, req: dict[str, Any]) -> None:
        """Ingests concurrent request life cycle into timeline."""
        req_id = req.get("request_id", 0)
        prog = req.get("program_name", "UNKNOWN_PROGRAM")
        start = req.get("actual_start_date")
        compl = req.get("actual_completion_date")
        status = req.get("status_code", "UNKNOWN")

        if start:
            self.add_event(
                original_timestamp=start,
                source="CONCURRENT_REQUEST",
                event_type="STAGE_START",
                entity_id=f"REQ_{req_id}_{prog}",
                summary=f"Concurrent program {prog} (Request {req_id}) started execution.",
                details=req,
            )
        if compl:
            is_err = status in ("ERROR", "E", "TERMINATED", "X")
            self.add_event(
                original_timestamp=compl,
                source="CONCURRENT_REQUEST",
                event_type="ERROR" if is_err else "COMPLETION",
                entity_id=f"REQ_{req_id}_{prog}",
                summary=f"Concurrent program {prog} (Request {req_id}) completed with status: {status}.",
                details=req,
            )

    def build_correlated_timeline(self) -> dict[str, Any]:
        """Sorts all ingested events chronologically, isolates the upstream root trigger,
        and tags downstream cascading events.
        """
        # Chronological sort
        self.events.sort(key=lambda e: e.timestamp_unix)

        # Causal isolation: The earliest ERROR or LOCK_HOLD event is the primary root cause candidate
        root_trigger: TimelineEvent | None = None
        for ev in self.events:
            if ev.event_type in ("ERROR", "LOCK_HOLD") and not root_trigger:
                ev.is_causal_trigger = True
                root_trigger = ev
                break

        cascading = [e for e in self.events if e != root_trigger and e.event_type in ("ERROR", "LOCK_WAIT")]

        start_time = self.events[0].timestamp_utc if self.events else "N/A"
        end_time = self.events[-1].timestamp_utc if self.events else "N/A"

        return {
            "incident_id": self.incident_id,
            "total_events": len(self.events),
            "start_time_utc": start_time,
            "end_time_utc": end_time,
            "root_trigger_event": root_trigger.to_dict() if root_trigger else None,
            "cascading_events_count": len(cascading),
            "timeline": [e.to_dict() for e in self.events],
        }
