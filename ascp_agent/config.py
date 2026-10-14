"""Enterprise Configuration for ASCP Collections Diagnostic Agent.
Includes Oracle connection profiles, ITSM endpoints, guardrail limits, and runtime flags.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def load_env_file(dotenv_path: str | None = None) -> None:
    """Load key-value environment variables from .env file if present."""
    if dotenv_path is None:
        dotenv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
    if not os.path.isfile(dotenv_path):
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path)
    except ImportError:
        try:
            with open(dotenv_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
        except OSError:
            pass


load_env_file()


def _resolve_use_simulation() -> bool:
    if os.getenv("ORACLE_SIMULATION", "").lower() in ("false", "0", "no"):
        return False
    if os.getenv("RUN_REAL_ORACLE", "").lower() in ("true", "1", "yes"):
        return False
    if os.getenv("FORCE_SIMULATION_MODE") == "1" or os.getenv("DISABLE_EXTERNAL_CALLS") == "1":
        return True
    if "USE_MOCK_DB" in os.environ:
        return os.getenv("USE_MOCK_DB", "").lower() in ("true", "1", "yes")
    return os.getenv("ORACLE_SIMULATION", "true").lower() in ("true", "1", "yes")


class ConfigValidationError(RuntimeError, ValueError):
    """Raised when configuration fails fail-closed validation."""

@dataclass
class OracleConfig:
    host: str = field(default_factory=lambda: os.getenv("ORACLE_HOST", "ebs-db.corp.internal"))
    port: int = field(default_factory=lambda: int(os.getenv("ORACLE_PORT", "1521")))
    service_name: str = field(
        default_factory=lambda: os.getenv("ORACLE_SERVICE_NAME") or os.getenv("ORACLE_SERVICE", "EBSPROD")
    )
    username: str = field(default_factory=lambda: os.getenv("ORACLE_USER", "APPS_DIAG"))
    password: str = field(default_factory=lambda: os.getenv("ORACLE_PASSWORD", ""), repr=False)
    diagnostic_role: str = "SELECT_CATALOG_ROLE"
    # Principle of Least Privilege: Separate remediation credentials
    remediation_username: str = field(default_factory=lambda: os.getenv("ORACLE_REMEDIATION_USER", "APPS_REMEDIATE"))
    remediation_password: str = field(default_factory=lambda: os.getenv("ORACLE_REMEDIATION_PASSWORD", ""), repr=False)
    remediation_role: str = "APPS_WRAPPER_EXECUTE"
    mode: str = field(default_factory=lambda: os.getenv("ORACLE_DRIVER_MODE", "thin"))
    use_simulation: bool = field(default_factory=_resolve_use_simulation)
    min_pool_size: int = 1
    max_pool_size: int = 5
    pool_increment: int = 1
    # ASCP Collection Profile Options
    source_setup_required: str = "Yes"                  # MSC: Source Setup Required
    purge_stg_tbl_cntrl: str = "Yes"                     # MSC: Purge Stg Tbl Cntrl
    refresh_snapshots_timeout_min: int = 120             # MSC: Refresh Snapshots Pending Timeout
    purge_batch_size: int = 25000                        # MRP: Purge Batch Size
    db_links: dict[str, str] = field(default_factory=lambda: {"source_to_aps": "A2M_DBLINK", "aps_to_source": "M2A_DBLINK"})

    def __post_init__(self) -> None:
        if not self.use_simulation and not self.password:
            raise ConfigValidationError("ORACLE_PASSWORD must be set when ORACLE_SIMULATION is false. (ORACLE_PASSWORD is empty or unset)")

    def validate(self) -> None:
        """Fail-closed validation: ensure production credentials exist if simulation is disabled."""
        self.__post_init__()
        if not self.use_simulation and self.host == "ebs-db.corp.internal":
            raise ConfigValidationError("Production connection cannot target default mock endpoint 'ebs-db.corp.internal'.")

@dataclass
class ServiceNowConfig:
    instance_url: str = field(default_factory=lambda: os.getenv("SN_INSTANCE_URL", "https://enterprise-it.service-now.com"))
    table_api_path: str = "/api/now/table/incident"
    username: str = field(default_factory=lambda: os.getenv("SN_USER", "ascp_agent_svc"))
    password: str = field(default_factory=lambda: os.getenv("SN_PASSWORD", ""), repr=False)
    assignment_group: str = "Database Administration"
    default_impact: str = "2"
    default_urgency: str = "2"
    enabled: bool = field(default_factory=lambda: os.getenv("SN_ENABLED", "true").lower() == "true")
    dry_run: bool = field(default_factory=lambda: os.getenv("SN_DRY_RUN", "true").lower() == "true")

    def __post_init__(self) -> None:
        if self.enabled and not self.dry_run and not self.password:
            raise ConfigValidationError("SN_PASSWORD must be set when SN_ENABLED is true and SN_DRY_RUN is false. (SN_PASSWORD is empty or unset)")

    def validate(self) -> None:
        """Fail-closed validation: ensure ServiceNow credentials exist if live dispatch is enabled."""
        self.__post_init__()

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
        "APPS.SNAPSHOT_REFRESH_WRAPPER",
        "MSC_CL_PULL.PURGE_STAGING_TABLES_SUB",
        "MSC_CL_COLLECTION.PURGE_STAGING_TABLES_SUB",
        "DBMS_PIPE.PURGE",
        "DBMS_SNAPSHOT.REFRESH",
        "MSC_CL_EXCHANGE_PARTTN.ALIGN_INDEX_DEFS"
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
