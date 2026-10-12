"""Enterprise Security & Guardrail Architecture.
Enforces defense-in-depth safety boundaries:
1. Least-Privilege Access Control on SQL/PLSQL execution
2. Input/Output Prompt Sanitization & Jailbreak Defense
3. Execution Loop Super-Step Caps (Max 10 steps)
4. Hard Token Spend Caps ($5.00 limit per diagnostic session)
"""

import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from ascp_agent.config import GuardrailsConfig

class SecurityViolationError(Exception):
    """Raised when an action violates enterprise security guardrails."""
    pass

class ExecutionCapExceededError(Exception):
    """Raised when graph execution reaches the maximum super-step threshold."""
    pass

class TokenSpendCapExceededError(Exception):
    """Raised when cumulative token spend exceeds the dollar threshold."""
    pass

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

_KILL_PATTERN = re.compile(r"^ALTER SYSTEM KILL SESSION '\d+,\d+' IMMEDIATE$")

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

        # 3. Allowlisted procedural remediation calls (BEGIN / EXEC)
        for procedure in self.config.allowed_mutation_procedures:
            proc_up = procedure.upper()
            if upper.startswith(f"BEGIN {proc_up}(") or upper.startswith(f"EXEC {proc_up}("):
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

        for procedure in getattr(self.config, "allowed_mutation_procedures", []):
            proc_up = procedure.upper()
            if upper.startswith(f"BEGIN {proc_up}(") or upper.startswith(f"EXEC {proc_up}("):
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
