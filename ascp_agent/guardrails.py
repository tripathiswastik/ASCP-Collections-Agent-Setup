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
        """Allow only single read-only queries, an exact kill statement, or allowlisted procedures."""
        if not self.config.enforce_least_privilege:
            return True
        statement = sql_statement.strip().rstrip(";").strip()
        upper = statement.upper()
        if upper.startswith(("SELECT ", "WITH ")):
            if ";" in statement:
                raise SecurityViolationError("Multiple statements are not allowed.")
            return True
        if _KILL_PATTERN.match(upper):
            return True  # approval for this is enforced by the HITL gate, not here
        for procedure in self.config.allowed_mutation_procedures:
            proc_up = procedure.upper()
            if upper.startswith(f"BEGIN {proc_up}(") or upper.startswith(f"EXEC {proc_up}("):
                return True
        if ";" in statement:
            raise SecurityViolationError("Multiple statements are not allowed.")
        raise SecurityViolationError(f"Statement not on the allowlist: {statement[:80]}")

    def track_tokens(self, input_tokens: int, output_tokens: int):
        """Tracks token expenditure against the $5.00 hard cap."""
        self.token_tracker.record_usage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_in_1k=self.config.token_cost_per_1k_input,
            cost_out_1k=self.config.token_cost_per_1k_output
        )
