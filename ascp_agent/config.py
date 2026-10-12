"""Enterprise Configuration for ASCP Collections Diagnostic Agent.
Includes Oracle connection profiles, ITSM endpoints, guardrail limits, and runtime flags.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, Any

@dataclass
class OracleConfig:
    host: str = os.getenv("ORACLE_HOST", "ebs-db.corp.internal")
    port: int = int(os.getenv("ORACLE_PORT", "1521"))
    service_name: str = os.getenv("ORACLE_SERVICE", "EBSPROD")
    username: str = os.getenv("ORACLE_USER", "APPS_DIAG")
    password: str = os.getenv("ORACLE_PASSWORD", "")  # No hardcoded password; load via environment or vault
    mode: str = os.getenv("ORACLE_DRIVER_MODE", "thin")  # thin driver or thick
    use_simulation: bool = os.getenv("ORACLE_SIMULATION", "true").lower() == "true"
    # ASCP Collection Profile Options
    source_setup_required: str = "Yes"                  # MSC: Source Setup Required
    purge_stg_tbl_cntrl: str = "Yes"                     # MSC: Purge Stg Tbl Cntrl
    refresh_snapshots_timeout_min: int = 120             # MSC: Refresh Snapshots Pending Timeout
    purge_batch_size: int = 25000                        # MRP: Purge Batch Size
    db_links: Dict[str, str] = field(default_factory=lambda: {"source_to_aps": "A2M_DBLINK", "aps_to_source": "M2A_DBLINK"})

    def validate(self) -> None:
        """Fail-closed validation: ensure production credentials exist if simulation is disabled."""
        if not self.use_simulation:
            if not self.password or not self.password.strip():
                raise ValueError(
                    "Production Oracle integration failed closed: ORACLE_PASSWORD is empty or unset. "
                    "Set ORACLE_PASSWORD in the environment or enable ORACLE_SIMULATION=true."
                )
            if self.host in ("ebs-db.corp.internal", "localhost", "127.0.0.1") and not os.getenv("ORACLE_ALLOW_LOCAL"):
                # Default mock host shouldn't be used in production mode
                raise ValueError(
                    f"Production Oracle integration failed closed: host '{self.host}' is configured with default mock endpoint. "
                    "Specify a valid production database host via ORACLE_HOST."
                )

@dataclass
class ServiceNowConfig:
    instance_url: str = os.getenv("SN_INSTANCE_URL", "https://enterprise-it.service-now.com")
    table_api_path: str = "/api/now/table/incident"
    username: str = os.getenv("SN_USER", "ascp_agent_svc")
    password: str = os.getenv("SN_PASSWORD", "")  # No hardcoded password; load via environment or vault
    assignment_group: str = "Database Administration"
    default_impact: str = "2"
    default_urgency: str = "2"
    enabled: bool = os.getenv("SN_ENABLED", "true").lower() == "true"
    dry_run: bool = os.getenv("SN_DRY_RUN", "true").lower() == "true"

    def validate(self) -> None:
        """Fail-closed validation: ensure ServiceNow credentials exist if live dispatch is enabled."""
        if self.enabled and not self.dry_run:
            if not self.password or not self.password.strip():
                raise ValueError(
                    "Production ServiceNow integration failed closed: SN_PASSWORD is empty or unset. "
                    "Set SN_PASSWORD in the environment or enable SN_DRY_RUN=true."
                )

@dataclass
class GuardrailsConfig:
    max_super_steps: int = 10                  # Hard cap on graph execution loops
    hard_token_spend_cap_usd: float = 5.00     # Hard dollar spend cap per run
    token_cost_per_1k_input: float = 0.00015   # Gemini / LLM pricing model
    token_cost_per_1k_output: float = 0.00060
    enforce_least_privilege: bool = True       # Enforce read-only V$ dynamic views & PL/SQL wrappers
    allowed_mutation_procedures: tuple = (
        "APPS.MSCPDCP_WRAPPER",
        "APPS.KILL_SESSION_WRAPPER",
        "APPS.PIPE_RESET_WRAPPER",
        "APPS.SNAPSHOT_REFRESH_WRAPPER"
    )

@dataclass
class AgentConfig:
    oracle: OracleConfig = field(default_factory=OracleConfig)
    servicenow: ServiceNowConfig = field(default_factory=ServiceNowConfig)
    guardrails: GuardrailsConfig = field(default_factory=GuardrailsConfig)
    thread_id: str = "ascp-session-default"
    log_level: str = "INFO"

    def validate(self) -> None:
        """Validate all sub-configurations."""
        self.oracle.validate()
        self.servicenow.validate()

DEFAULT_CONFIG = AgentConfig()
