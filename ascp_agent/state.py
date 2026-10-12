"""Typed State Schema and Primitives for the ASCP Diagnostic Control Plane.
Includes field-level reducers (add_messages, operator.add), Command, and interrupt primitives.
Compatible with standard LangGraph and includes a self-contained runtime engine.
"""

import operator
from typing import List, Dict, Any, Optional, Union, Callable

# Check for typing_extensions for Python < 3.9 Annotated support
try:
    from typing import TypedDict, Annotated
except ImportError:
    try:
        from typing_extensions import TypedDict, Annotated
    except ImportError:
        # Fallback TypedDict
        TypedDict = dict
        Annotated = None

# Message definitions
class Message:
    def __init__(self, content: str, role: str = "assistant"):
        self.content = content
        self.role = role

    def to_dict(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}

    def __repr__(self):
        return f"{self.__class__.__name__}(content={self.content!r})"

class HumanMessage(Message):
    def __init__(self, content: str):
        super().__init__(content=content, role="user")

class AIMessage(Message):
    def __init__(self, content: str):
        super().__init__(content=content, role="assistant")

AnyMessage = Union[Message, HumanMessage, AIMessage, Dict[str, str]]

def add_messages(existing: List[AnyMessage], new_msgs: Union[List[AnyMessage], AnyMessage]) -> List[AnyMessage]:
    """Reducer that appends new messages to the message history."""
    if existing is None:
        existing = []
    result = list(existing)
    if isinstance(new_msgs, list):
        result.extend(new_msgs)
    elif new_msgs is not None:
        result.append(new_msgs)
    return result

class Command:
    """LangGraph Command primitive packaging state updates and dynamic destination routing."""
    def __init__(self, update: Optional[Dict[str, Any]] = None, goto: Optional[str] = None, resume: Any = None):
        self.update = update or {}
        self.goto = goto
        self.resume = resume

class InterruptSignal(Exception):
    """Exception raised by interrupt() to pause graph execution for human sign-off."""
    def __init__(self, payload: Dict[str, Any]):
        super().__init__("Graph paused for human sign-off.")
        self.payload = payload

def interrupt(payload: Dict[str, Any]) -> Any:
    """Pauses graph execution, persists state, and surfaces the payload to an operator."""
    raise InterruptSignal(payload)

class DiagnosticContext(dict):
    """Context dictionary tracking request metadata, errors, and lock hierarchy."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setdefault("concurrent_request_id", 890415)
        self.setdefault("failed_phase", "LOAD")  # PULL, LOAD, PURGE
        self.setdefault("target_staging_table", "MSC_ST_DEMANDS")
        self.setdefault("detected_errors", [])
        self.setdefault("lock_hierarchy", [])
        self.setdefault("remediation_action", None)
        self.setdefault("recommended_playbook", "KILL_SESSION")

# Typed Diagnostic / Agent State definition
class AgentState(dict):
    """Typed AgentState schema for LangGraph control plane with explicit field reducers."""
    
    # Reducer schema mapping
    _reducers = {
        "messages": add_messages,
        "lock_telemetry": operator.add,
        "log_templates": operator.add,
        "raw_logs": operator.add,
        "audit_trail": operator.add
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Ensure default field structure
        self.setdefault("messages", [])
        self.setdefault("context", DiagnosticContext())
        self.setdefault("lock_telemetry", [])
        self.setdefault("log_templates", [])
        self.setdefault("raw_logs", [])
        self.setdefault("audit_trail", [])
        self.setdefault("failure_domain", "DATABASE_LOCK")  # DATABASE_LOCK, STAGING_VALIDATION, INFRASTRUCTURE
        self.setdefault("confidence_score", 0.0)             # 0.0 to 100.0
        self.setdefault("risk_level", "HIGH")               # LOW, MEDIUM, HIGH
        self.setdefault("is_remediated", False)
        self.setdefault("root_blocker_found", False)
        self.setdefault("remediation_action", "INSPECT_LOCKS")
        self.setdefault("remediation_approved", False)
        self.setdefault("recovery_command", None)
        self.setdefault("interrupted", False)
        self.setdefault("interrupt_payload", None)
        self.setdefault("completed", False)
        self.setdefault("servicenow_incident", None)

    def apply_update(self, update_dict: Dict[str, Any]):
        """Apply partial dictionary update respecting field reducers."""
        for k, v in update_dict.items():
            if k in self._reducers and k in self and self[k] is not None:
                reducer = self._reducers[k]
                self[k] = reducer(self[k], v)
            elif k == "context" and isinstance(v, dict):
                # Merge context updates
                self["context"].update(v)
            else:
                self[k] = v

# Backward compatibility alias
DiagnosticState = AgentState
