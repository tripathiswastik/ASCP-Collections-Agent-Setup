"""Enterprise Security & Guardrail Architecture.
Enforces defense-in-depth safety boundaries:
1. Least-Privilege Access Control on SQL/PLSQL execution
2. Input/Output Prompt Sanitization & Jailbreak Defense
3. Execution Loop Super-Step Caps (Max 10 steps)
4. Hard Token Spend Caps ($5.00 limit per diagnostic session)
"""

import re
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Union
from ascp_agent.config import GuardrailsConfig

class SecurityViolationError(Exception):
    """Raised when an action violates enterprise security guardrails."""
    pass

class BlastRadiusViolationError(SecurityViolationError):
    """Raised when an action violates session termination blast-radius limits."""
    pass

class ExecutionCapExceededError(Exception):
    """Raised when graph execution reaches the maximum super-step threshold."""
    pass

class TokenSpendCapExceededError(Exception):
    """Raised when cumulative token spend exceeds the dollar threshold."""
    pass

# Protected Oracle system schemas that must NEVER be terminated
FORBIDDEN_USERS = {
    "SYS", "SYSTEM", "DBSNMP", "SYSMAN", "OUTLN", "AUDSYS",
    "GSMADMIN_INTERNAL", "APPQOSSYS", "ORDDATA", "CTXSYS",
    "MDSYS", "ANONYMOUS", "XDB", "WMSYS", "LBACSYS", "MGMT_VIEW"
}

# Permitted EBS & ASCP schemas
ALLOWED_EBS_USERS = {
    "APPS", "MSC", "APPLSYS", "APPLSYSPUB", "MRP", "INV", "ONT", "PO", "WIP", "BOM"
}

# Permitted module prefixes / names for EBS concurrent workers & batch jobs
ALLOWED_MODULE_PATTERNS = [
    re.compile(r"^MSC", re.IGNORECASE),
    re.compile(r"^MSRFWOR", re.IGNORECASE),
    re.compile(r"^DISCO", re.IGNORECASE),
    re.compile(r"^SQL\*Plus", re.IGNORECASE),
    re.compile(r"^TOAD", re.IGNORECASE),
    re.compile(r"^e:MSC", re.IGNORECASE),
    re.compile(r"^concurrent", re.IGNORECASE),
    re.compile(r"^JDBC Thin Client", re.IGNORECASE),
    re.compile(r"^FND_", re.IGNORECASE),
]

def validate_session_kill_safety(
    target_sid: int,
    target_serial: int,
    username: Optional[str] = None,
    module: Optional[str] = None,
    session_type: Optional[str] = "USER",
    self_sid: Optional[int] = None
) -> None:
    """Enforces blast-radius safety checks:
    1. Never kill sessions owned by SYS or Oracle system schemas.
    2. Never kill background processes (TYPE = 'BACKGROUND').
    3. Never kill agent's own session (self_sid).
    4. Only allow kills where module or username matches EBS / ASCP batch pattern.
    """
    if self_sid is not None and target_sid == self_sid:
        raise BlastRadiusViolationError(
            f"Blast radius protection: Refusing to kill agent's own active database session (SID {target_sid})."
        )

    if session_type and session_type.strip().upper() == "BACKGROUND":
        raise BlastRadiusViolationError(
            f"Blast radius protection: Refusing to kill Oracle background kernel session (SID {target_sid})."
        )

    if username:
        clean_user = username.strip().upper()
        if clean_user in FORBIDDEN_USERS:
            raise BlastRadiusViolationError(
                f"Blast radius protection: Refusing to kill protected system session owned by '{username}' (SID {target_sid})."
            )

        # If user is not an allowed EBS user, verify module matches EBS/ASCP batch pattern
        if clean_user not in ALLOWED_EBS_USERS:
            mod_str = module or ""
            is_ebs_mod = any(pat.search(mod_str) for pat in ALLOWED_MODULE_PATTERNS)
            if not is_ebs_mod:
                raise BlastRadiusViolationError(
                    f"Blast radius protection: Session SID {target_sid} (User '{username}', Module '{mod_str}') "
                    f"does not match recognized EBS/ASCP batch worker or application patterns."
                )

@dataclass
class KillRateLimiter:
    """Enforces cooldown (max 1 kill per instance per N minutes) and daily cap."""
    cooldown_seconds: int = 300  # 5 minutes
    daily_cap: int = 5           # Max 5 kills per 24 hours per instance
    _history: Dict[str, List[float]] = field(default_factory=dict)

    def reset(self) -> None:
        """Clear limiter history (useful for test isolation)."""
        self._history.clear()

    def check_and_record_kill(
        self,
        instance_id: Any,
        dry_run: bool = False,
        now: Optional[float] = None,
        force_override: bool = False
    ) -> None:
        import os
        if dry_run or force_override or os.environ.get("ASCP_DISABLE_KILL_LIMITER", "").lower() in ("1", "true"):
            return
        now_ts = now if now is not None else time.time()
        key = str(instance_id or "1001")
        history = self._history.setdefault(key, [])
        # Retain only entries from the last 24 hours
        active_24h = [t for t in history if now_ts - t < 86400]
        self._history[key] = active_24h

        if active_24h:
            elapsed_since_last = now_ts - active_24h[-1]
            if elapsed_since_last < self.cooldown_seconds:
                remaining = int(self.cooldown_seconds - elapsed_since_last)
                raise BlastRadiusViolationError(
                    f"Blast radius cooldown active for instance '{key}'. "
                    f"Minimum {self.cooldown_seconds}s required between kills ({remaining}s remaining)."
                )

        if len(active_24h) >= self.daily_cap:
            raise BlastRadiusViolationError(
                f"Daily kill cap of {self.daily_cap} reached for instance '{key}'. "
                f"Automated remediation halted to prevent cascading instability. Requires manual DBA evaluation."
            )

        active_24h.append(now_ts)
        self._history[key] = active_24h

# Global singleton kill limiter
GLOBAL_KILL_LIMITER = KillRateLimiter()

class RemediationActionEnum(str, Enum):
    INSPECT_LOCKS = "INSPECT_LOCKS"
    KILL_SESSION = "KILL_SESSION"
    PURGE_STAGING = "PURGE_STAGING"
    ALIGN_INDEXES = "ALIGN_INDEXES"
    REFRESH_SNAPSHOT = "REFRESH_SNAPSHOT"
    PURGE_PIPE = "PURGE_PIPE"
    RESET_REGISTRY = "RESET_REGISTRY"
    EXTEND_UNDO_RETENTION = "EXTEND_UNDO_RETENTION"
    EXTEND_TABLESPACE = "EXTEND_TABLESPACE"
    FLUSH_SHARED_POOL = "FLUSH_SHARED_POOL"
    RETRY_CONCURRENT_REQUEST = "RETRY_CONCURRENT_REQUEST"
    NO_ACTION = "NO_ACTION"

@dataclass
class TypedActionRequest:
    action: RemediationActionEnum
    sid: Optional[int] = None
    serial: Optional[int] = None
    inst_id: Optional[int] = None
    target_object: Optional[str] = None
    instance_id: Optional[int] = None

def validate_action_from_untrusted_data(action_name: str, params: Optional[Dict[str, Any]] = None) -> TypedActionRequest:
    """Validates that action originates strictly from an enumerated set of safe actions
    and typed parameters, ensuring prompt injection cannot emit executable SQL or unauthorized commands.
    """
    try:
        enum_val = RemediationActionEnum(str(action_name).strip().upper())
    except (ValueError, AttributeError):
        raise SecurityViolationError(f"Action '{action_name}' is not in the allowed enumerated remediation actions.")

    params = params or {}
    sid = params.get("sid")
    serial = params.get("serial")
    inst_id = params.get("inst_id")
    target_obj = params.get("target_object")
    instance_id = params.get("instance_id")

    return TypedActionRequest(
        action=enum_val,
        sid=int(sid) if sid is not None else None,
        serial=int(serial) if serial is not None else None,
        inst_id=int(inst_id) if inst_id is not None else None,
        target_object=str(target_obj) if target_obj is not None else None,
        instance_id=int(instance_id) if instance_id is not None else None
    )

@dataclass
class TokenTracker:
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    spend_cap_usd: float = 5.00

    def record_usage(self, input_tokens: int, output_tokens: int, cost_in_1k: float = 0.00015, cost_out_1k: float = 0.00060):
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        step_cost = ((input_tokens / 1000.0) * cost_in_1k) + ((output_tokens / 1000.0) * cost_out_1k)
        self.total_cost_usd += step_cost

        if self.total_cost_usd >= self.spend_cap_usd:
            raise TokenSpendCapExceededError(
                f"Hard token spend cap of ${self.spend_cap_usd:.2f} exceeded! Current spend: ${self.total_cost_usd:.4f}. Human escalation triggered."
            )

_KILL_PATTERN = re.compile(r"^ALTER SYSTEM KILL SESSION '\d+,\d+(?:,@\d+)?' IMMEDIATE$")
_CALL_PATTERN = re.compile(r"^(?:BEGIN|EXEC) ([A-Z0-9_$#.]+)\((.*)\)(?:; END)?$")
_SAFE_ARGUMENTS = re.compile(r"^[A-Z0-9_$#.,=> ']*$")
_REGISTRY_RESET_PATTERN = re.compile(r"^UPDATE MSC_APPS_INSTANCES SET ST_STATUS = 0 WHERE INSTANCE_ID = \d+$")
_FLUSH_POOL_PATTERN = re.compile(r"^ALTER SYSTEM FLUSH SHARED_POOL$")
_UNDO_RETENTION_PATTERN = re.compile(r"^ALTER SYSTEM SET UNDO_RETENTION = \d+(?: SCOPE=(?:BOTH|SPFILE|MEMORY))?$")
_EXTEND_TS_PATTERN = re.compile(r"^ALTER TABLESPACE [A-Z0-9_$#]+ ADD DATAFILE SIZE \d+[KMGT] AUTOEXTEND ON NEXT \d+[KMGT]$")

class EnterpriseGuardrails:
    """Enforces least-privilege, sanitization, step limits, and cost controls."""

    # Patterns indicating SQL injection or unauthorized destruction
    FORBIDDEN_SQL_PATTERNS = [
        re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
        re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE),
        re.compile(r"\bTRUNCATE\s+TABLE\s+(?!MSC_ST_)", re.IGNORECASE), # Only MSC_ST_* truncations allowed via wrapper
        re.compile(r"\bGRANT\s+ALL\b", re.IGNORECASE),
        re.compile(r"\bALTER\s+USER\b", re.IGNORECASE),
        re.compile(r"\bXP_CMDSHELL\b", re.IGNORECASE)
    ]

    # Prompt injection patterns
    PROMPT_INJECTION_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"system\s+prompt\s+override", re.IGNORECASE),
        re.compile(r"bypass\s+security\s+checks", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+in\s+dan\s+mode", re.IGNORECASE)
    ]

    def __init__(self, config: Optional[GuardrailsConfig] = None):
        self.config = config or GuardrailsConfig()
        self.token_tracker = TokenTracker(spend_cap_usd=self.config.hard_token_spend_cap_usd)
        self.step_counter = 0

    def check_super_step_limit(self):
        """Ensures graph execution does not exceed max super-steps (max 10)."""
        self.step_counter += 1
        if self.step_counter > self.config.max_super_steps:
            raise ExecutionCapExceededError(
                f"Execution loop cap exceeded ({self.config.max_super_steps} super-steps). Preventing runaway looping on tool failures."
            )

    def sanitize_input_prompt(self, user_or_log_text: str) -> str:
        """Sanitizes incoming prompts and log text for jailbreaking tokens."""
        for pattern in self.PROMPT_INJECTION_PATTERNS:
            if pattern.search(user_or_log_text):
                raise SecurityViolationError(
                    f"Prompt injection detected in input stream: pattern '{pattern.pattern}' matched."
                )
        return user_or_log_text.strip()

    def validate_sql_command(self, sql_statement: str) -> bool:
        """Allow only single read-only queries, an exact kill statement, or allowlisted procedures.
        Strips comments, forbids multiple statements, and inspects tokens to prevent DML/DDL bypasses.
        """
        if not self.config.enforce_least_privilege:
            return True

        if not sql_statement or not isinstance(sql_statement, str):
            raise SecurityViolationError("Empty or invalid SQL statement.")

        # 1. Strip single-line and multi-line comments to expose hidden statement injections
        cleaned = re.sub(r"--[^\r\n]*", " ", sql_statement)
        cleaned = re.sub(r"/\*.*?\*/", " ", cleaned, flags=re.DOTALL)
        cleaned = cleaned.strip().rstrip(";").strip()
        upper = cleaned.upper()

        # 2. Exact ALTER SYSTEM KILL SESSION validation
        if _KILL_PATTERN.match(upper):
            return True

        if _REGISTRY_RESET_PATTERN.match(upper):
            return True

        if _FLUSH_POOL_PATTERN.match(upper) or _UNDO_RETENTION_PATTERN.match(upper) or _EXTEND_TS_PATTERN.match(upper):
            return True

        if self._is_allowed_call(upper):
            return True

        # 4. Read-only query validation (SELECT / WITH)
        if upper.startswith(("SELECT ", "WITH ")):
            if ";" in cleaned:
                raise SecurityViolationError("Multiple statements are not allowed in read-only queries.")
            # Verify no mutation or execution verbs are smuggled inside CTEs or subqueries
            mutation_tokens = re.compile(
                r"\b(INSERT|UPDATE|DELETE|MERGE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|"
                r"RENAME|REPLACE|EXEC|EXECUTE|CALL|DECLARE|COMMIT|ROLLBACK|SAVEPOINT|LOCK)\b",
                re.IGNORECASE
            )
            match = mutation_tokens.search(cleaned)
            if match:
                raise SecurityViolationError(
                    f"Forbidden mutation keyword '{match.group(1)}' detected in read-only diagnostic query."
                )
            return True

        if ";" in cleaned:
            raise SecurityViolationError("Multiple statements are not allowed.")

        raise SecurityViolationError(f"Statement not on the allowlist: {sql_statement[:80]}")

    def _is_allowed_call(self, upper_statement: str) -> bool:
        """True only for a single allowlisted procedure call with simple literal arguments."""
        match = _CALL_PATTERN.match(upper_statement)
        if match is None:
            return False
        procedure, arguments = match.group(1), match.group(2)
        allowed = {name.upper() for name in getattr(self.config, "allowed_mutation_procedures", [])}
        return procedure in allowed and _SAFE_ARGUMENTS.match(arguments) is not None

    def validate_diagnostic_query(self, sql_statement: str, execution_role: str = "SELECT_CATALOG_ROLE") -> bool:
        """Enforces execution boundary for read-only diagnostic telemetry queries.
        Ensures execution occurs strictly under diagnostic credentials (e.g. SELECT_CATALOG_ROLE)
        and explicitly rejects any DML, DDL, DCL, or remediation kill statements.
        """
        if execution_role != getattr(self.config, "diagnostic_role", "SELECT_CATALOG_ROLE"):
            raise SecurityViolationError(
                f"Unauthorized diagnostic execution role '{execution_role}'. "
                f"Diagnostics must run strictly under read-only '{getattr(self.config, 'diagnostic_role', 'SELECT_CATALOG_ROLE')}'."
            )

        if not sql_statement or not isinstance(sql_statement, str):
            raise SecurityViolationError("Empty or invalid SQL statement.")

        cleaned = re.sub(r"--[^\r\n]*", " ", sql_statement)
        cleaned = re.sub(r"/\*.*?\*/", " ", cleaned, flags=re.DOTALL).strip().rstrip(";").strip()
        upper = cleaned.upper()

        if ";" in cleaned:
            raise SecurityViolationError("Multiple statements are forbidden in diagnostic queries.")

        # Explicitly forbid session termination or procedure calls in diagnostic channel
        if _KILL_PATTERN.match(upper) or upper.startswith(("ALTER ", "EXEC ", "BEGIN ")):
            raise SecurityViolationError(
                "Remediation actions cannot execute through the diagnostic read-only channel."
            )

        if not upper.startswith(("SELECT ", "WITH ")):
            raise SecurityViolationError("Diagnostic queries must start with SELECT or WITH.")

        mutation_tokens = re.compile(
            r"\b(INSERT|UPDATE|DELETE|MERGE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|"
            r"RENAME|REPLACE|EXEC|EXECUTE|CALL|DECLARE|COMMIT|ROLLBACK|SAVEPOINT|LOCK)\b",
            re.IGNORECASE
        )
        match = mutation_tokens.search(cleaned)
        if match:
            raise SecurityViolationError(
                f"Forbidden mutation keyword '{match.group(1)}' detected in read-only diagnostic query."
            )
        return True

    def validate_remediation_command(
        self,
        sql_statement: str,
        execution_role: str = "APPS_WRAPPER_EXECUTE",
        is_hitl_approved: bool = False,
        approval_id: Optional[str] = None
    ) -> bool:
        """Enforces authorization boundary for high-risk remediation database mutations.
        Requires authenticated HITL sign-off with valid approval ID and separate execution credentials.
        """
        if not is_hitl_approved or not approval_id:
            raise SecurityViolationError(
                "Remediation execution boundary rejected: Missing mandatory HITL sign-off and approval ID."
            )

        expected_role = getattr(self.config, "remediation_role", "APPS_WRAPPER_EXECUTE")
        if execution_role != expected_role:
            raise SecurityViolationError(
                f"Unauthorized remediation execution role '{execution_role}'. "
                f"Remediation requires privileged execution role '{expected_role}'."
            )

        if not sql_statement or not isinstance(sql_statement, str):
            raise SecurityViolationError("Empty or invalid remediation SQL statement.")

        cleaned = re.sub(r"--[^\r\n]*", " ", sql_statement)
        cleaned = re.sub(r"/\*.*?\*/", " ", cleaned, flags=re.DOTALL).strip().rstrip(";").strip()
        upper = cleaned.upper()

        if ";" in cleaned:
            raise SecurityViolationError("Chained or multiple statements are forbidden in remediation commands.")

        if _KILL_PATTERN.match(upper):
            return True

        if _REGISTRY_RESET_PATTERN.match(upper):
            return True

        if _FLUSH_POOL_PATTERN.match(upper) or _UNDO_RETENTION_PATTERN.match(upper) or _EXTEND_TS_PATTERN.match(upper):
            return True

        if self._is_allowed_call(upper):
            return True

        raise SecurityViolationError(f"Remediation statement not permitted: {sql_statement[:80]}")

    def track_tokens(self, input_tokens: int, output_tokens: int):
        """Tracks token expenditure against the $5.00 hard cap."""
        self.token_tracker.record_usage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_in_1k=self.config.token_cost_per_1k_input,
            cost_out_1k=self.config.token_cost_per_1k_output
        )
