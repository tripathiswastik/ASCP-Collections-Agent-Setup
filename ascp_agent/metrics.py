"""Operational Observability & Metrics Export Engine for ASCP Diagnostic Agent.
Tracks and exports:
- MTTR (Mean Time To Resolution)
- Operator Approval Latency
- Share of Diagnoses Approved vs. Rejected
- Share of diagnoses where the Agent was Wrong / Rolled Back
- Prometheus-compatible text format export
"""

import time
import threading
from typing import Dict, Any, List, Optional


class OperationalMetricsTracker:
    """Thread-safe collector for key operational metrics."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_diagnoses: int = 0
        self.total_approvals_requested: int = 0
        self.total_approvals_granted: int = 0
        self.total_approvals_rejected: int = 0
        self.wrong_diagnosis_count: int = 0
        self.approval_latencies: List[float] = []
        self.resolution_times: List[float] = []  # MTTR measurements

    def record_diagnosis(self, is_wrong: bool = False, duration_seconds: float = 0.0) -> None:
        with self._lock:
            self.total_diagnoses += 1
            if is_wrong:
                self.wrong_diagnosis_count += 1
            if duration_seconds > 0:
                self.resolution_times.append(duration_seconds)

    def record_approval_request(self) -> None:
        with self._lock:
            self.total_approvals_requested += 1

    def record_approval_decision(self, approved: bool, latency_seconds: float = 0.0) -> None:
        with self._lock:
            if approved:
                self.total_approvals_granted += 1
            else:
                self.total_approvals_rejected += 1
            if latency_seconds > 0:
                self.approval_latencies.append(latency_seconds)

    def record_resolution(self, mttr_seconds: float, was_successful: bool = True, was_wrong: bool = False) -> None:
        with self._lock:
            if mttr_seconds > 0 and was_successful:
                self.resolution_times.append(mttr_seconds)
            if was_wrong:
                self.wrong_diagnosis_count += 1

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            decisions_total = self.total_approvals_granted + self.total_approvals_rejected
            approved_share = round((self.total_approvals_granted / decisions_total), 4) if decisions_total > 0 else 0.0
            rejected_share = round((self.total_approvals_rejected / decisions_total), 4) if decisions_total > 0 else 0.0
            wrong_share = round((self.wrong_diagnosis_count / self.total_diagnoses), 4) if self.total_diagnoses > 0 else 0.0

            mean_latency = (
                round(sum(self.approval_latencies) / len(self.approval_latencies), 2)
                if self.approval_latencies else 0.0
            )
            mttr = (
                round(sum(self.resolution_times) / len(self.resolution_times), 2)
                if self.resolution_times else 0.0
            )

            return {
                "total_diagnoses": self.total_diagnoses,
                "total_approvals_requested": self.total_approvals_requested,
                "total_approvals_granted": self.total_approvals_granted,
                "total_approvals_rejected": self.total_approvals_rejected,
                "share_diagnoses_approved": approved_share,
                "share_diagnoses_rejected": rejected_share,
                "wrong_diagnosis_count": self.wrong_diagnosis_count,
                "share_wrong_diagnoses": wrong_share,
                "mean_approval_latency_seconds": mean_latency,
                "mean_time_to_resolve_seconds": mttr,
                "samples_approval_latency": len(self.approval_latencies),
                "samples_resolution_time": len(self.resolution_times),
            }

    def to_prometheus_format(self) -> str:
        s = self.get_summary()
        lines = [
            "# HELP ascp_diagnoses_total Total autonomous diagnoses performed.",
            "# TYPE ascp_diagnoses_total counter",
            f"ascp_diagnoses_total {s['total_diagnoses']}",
            "",
            "# HELP ascp_approvals_granted_total Approvals granted by DBA operators.",
            "# TYPE ascp_approvals_granted_total counter",
            f"ascp_approvals_granted_total {s['total_approvals_granted']}",
            "",
            "# HELP ascp_approvals_rejected_total Approvals rejected by DBA operators.",
            "# TYPE ascp_approvals_rejected_total counter",
            f"ascp_approvals_rejected_total {s['total_approvals_rejected']}",
            "",
            "# HELP ascp_approval_share_ratio Ratio of approved to total decided remediations.",
            "# TYPE ascp_approval_share_ratio gauge",
            f"ascp_approval_share_ratio {s['share_diagnoses_approved']}",
            "",
            "# HELP ascp_wrong_diagnoses_ratio Share of diagnoses that were incorrect or rolled back.",
            "# TYPE ascp_wrong_diagnoses_ratio gauge",
            f"ascp_wrong_diagnoses_ratio {s['share_wrong_diagnoses']}",
            "",
            "# HELP ascp_approval_latency_seconds Average time taken by operator to render decision.",
            "# TYPE ascp_approval_latency_seconds gauge",
            f"ascp_approval_latency_seconds {s['mean_approval_latency_seconds']}",
            "",
            "# HELP ascp_mttr_seconds Mean time to resolve pipeline stalls in seconds.",
            "# TYPE ascp_mttr_seconds gauge",
            f"ascp_mttr_seconds {s['mean_time_to_resolve_seconds']}",
        ]
        return "\n".join(lines) + "\n"


# Singleton instance for operational metric aggregation
GLOBAL_METRICS = OperationalMetricsTracker()
