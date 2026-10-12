"""ITSM ServiceNow REST API Integration Client.
Formats and dispatches structured diagnostic incident payloads to ServiceNow
Table REST API (POST /api/now/table/incident) for auditable DBA workflows.
"""

import logging
import time
import uuid
from typing import Dict, Any, Optional
from collections import deque
from ascp_agent.config import ServiceNowConfig

logger = logging.getLogger(__name__)

class ServiceNowClient:
    """Client for dispatching ASCP diagnostic incidents to ServiceNow Table API."""

    def __init__(self, config: Optional[ServiceNowConfig] = None):
        self.config = config or ServiceNowConfig()
        self.created_incidents = deque(maxlen=200)
        self._session = None

    def get_oauth_token_endpoint(self) -> str:
        """Dynamically constructs instance-specific OAuth token endpoint."""
        base_url = self.config.instance_url.rstrip("/") if self.config.instance_url else "https://instance.service-now.com"
        return f"{base_url}/oauth_token.do"

    def get_valid_oauth_token(self) -> str:
        """Retrieves simulated or cached OAuth access token."""
        return f"tok_sn_{uuid.uuid4().hex[:24]}"

    def build_incident_payload(
        self,
        short_description: str,
        description: str,
        pipeline_stage: str,
        instance_id: int,
        affected_staging_objects: list,
        root_blocker_session: Optional[Dict[str, Any]],
        drain_log_templates: list,
        recommended_remediation: str,
        agent_reasoning_trace: str,
        lock_hierarchy: Optional[list] = None,
        impact: str = "2",
        urgency: str = "2"
    ) -> Dict[str, Any]:
        """Constructs compliant ServiceNow Incident JSON payload enriched with DBA telemetry."""
        root = root_blocker_session or {}
        root_sid = root.get("sid")
        holding_sql_id = root.get("sql_id", "SQL_ID_ORA54_EXCL")
        holding_sql_text = root.get("current_sql_text", "N/A")
        lock_hierarchy = lock_hierarchy or ([root] if root else [])

        # Build one-click DBA remediation playbook
        playbook = {
            "primary_action": recommended_remediation,
            "session_kill_command": f"ALTER SYSTEM KILL SESSION '{root_sid},{root.get('serial_number')}' IMMEDIATE" if root_sid else None,
            "staging_purge_command": f"BEGIN MSC_CL_COLLECTION.PURGE_STAGING_TABLES_SUB(p_instance_id => {instance_id}, p_validation => 'N'); END;",
            "registry_normalization_sql": f"UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = {instance_id}; COMMIT;",
            "verification_query": "SELECT sid, serial#, locked_mode FROM v$locked_object lo JOIN dba_objects do ON lo.object_id = do.object_id WHERE do.object_name LIKE 'MSC_ST_%';"
        }

        return {
            "short_description": short_description,
            "assignment_group": self.config.assignment_group,
            "impact": impact,
            "urgency": urgency,
            "description": description,
            "u_diagnostic_payload": {
                "pipeline_stage": pipeline_stage,
                "instance_id": instance_id,
                "affected_staging_tables": affected_staging_objects,
                "affected_staging_objects": affected_staging_objects,
                "root_blocker_sid": root_sid,
                "root_blocker_session": root,
                "holding_sql_id": holding_sql_id,
                "holding_sql_text": holding_sql_text,
                "lock_duration_hierarchies": lock_hierarchy,
                "drain_log_templates": drain_log_templates,
                "recommended_remediation": recommended_remediation,
                "one_click_remediation_playbook": playbook,
                "agent_reasoning_trace": agent_reasoning_trace
            }
        }

    def build_incident_payload_from_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Convenience method that serializes a DiagnosticState dictionary into a compliant ServiceNow Incident payload."""
        from ascp_agent.remediation import format_recovery_command_block
        target_table = state.get("context", {}).get("target_staging_table", "MSC_ST_DEMANDS")
        failed_phase = state.get("context", {}).get("failed_phase", "LOAD")
        domain = state.get("failure_domain", "DATABASE_LOCK")
        confidence = state.get("confidence_score", 0.0)
        risk = state.get("risk_level", "HIGH")
        action = state.get("remediation_action", "KILL_SESSION")
        blocker = next((x for x in state.get("lock_telemetry", []) if x.get("lock_depth") == 1), {})
        instance_id = state.get("context", {}).get("instance_id", 1001)

        recovery_cmd = format_recovery_command_block(instance_id=instance_id, instance_code="PRD1", validation="N")

        return self.build_incident_payload(
            short_description=f"ASCP Collection Failure: {failed_phase} phase on {target_table}",
            description=f"Autonomous ASCP Diagnostic Agent detected {domain} on {target_table}. Confidence: {confidence:.1f}%.",
            pipeline_stage="Stage 2: Planning ODS Load (MSCPDC)",
            instance_id=instance_id,
            affected_staging_objects=[target_table],
            root_blocker_session=blocker,
            drain_log_templates=state.get("log_templates", []),
            recommended_remediation=f"Execute {action} and apply recovery command: {recovery_cmd}",
            agent_reasoning_trace=f"Domain: {domain}, Confidence: {confidence:.1f}%, Risk: {risk}.",
            lock_hierarchy=state.get("lock_telemetry", [])
        )

    def _simulated_result(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate auditable simulated ServiceNow ticket for dry-run and local testing."""
        incident_number = f"INC{int(time.time()) % 1000000:06d}"
        sys_id = f"sys_{uuid.uuid4().hex[:16]}"
        result = {
            "status": "SIMULATED_DISPATCH",
            "incident_number": incident_number,
            "sys_id": sys_id,
            "assignment_group": self.config.assignment_group,
            "endpoint": f"{self.config.instance_url}{self.config.table_api_path}",
            "payload": payload,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        self.created_incidents.append(result)
        return result

    def dispatch_incident(self, payload: Dict[str, Any], max_retries: int = 3) -> Dict[str, Any]:
        """POST an incident to ServiceNow. Returns status CREATED, SIMULATED_DISPATCH, SKIPPED or FAILED."""
        if not self.config.enabled:
            return {"status": "SKIPPED", "message": "ServiceNow dispatch disabled in config."}
        if self.config.dry_run or not self.config.instance_url:
            return self._simulated_result(payload)

        import requests
        if self._session is None:
            self._session = requests.Session()
        url = f"{self.config.instance_url.rstrip('/')}{self.config.table_api_path}"
        auth = (self.config.username, self.config.password)
        last_error = "no attempt made"

        for attempt in range(max_retries):
            try:
                resp = self._session.post(
                    url,
                    auth=auth,
                    json=payload,
                    timeout=10,
                    headers={"Accept": "application/json"}
                )
            except requests.RequestException as exc:
                last_error = f"request error: {exc}"
                break
            if resp.status_code in (200, 201):
                data = resp.json().get("result", {})
                result = {
                    "status": "CREATED",
                    "incident_number": data.get("number"),
                    "sys_id": data.get("sys_id"),
                    "payload": payload,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }
                self.created_incidents.append(result)
                return result
            if resp.status_code == 429:
                last_error = "HTTP 429 after retries"
                time.sleep((2 ** attempt) * 0.5 + 0.1)
                continue
            last_error = f"HTTP {resp.status_code}"
            break

        logger.error("ServiceNow dispatch failed: %s", last_error)
        return {
            "status": "FAILED",
            "error": last_error,
            "payload": payload,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
