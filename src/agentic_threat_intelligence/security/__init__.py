"""Security boundaries for identities, prompt trust and tool authorization."""

from .identity import PrincipalType, SecurityPrincipal
from .tool_authorization import (
    ToolAccessDecision,
    ToolAccessRule,
    ToolAuthorizationPolicy,
    ToolRisk,
)

__all__ = [
    "PrincipalType",
    "SecurityPrincipal",
    "ToolAccessDecision",
    "ToolAccessRule",
    "ToolAuthorizationPolicy",
    "ToolRisk",
]
