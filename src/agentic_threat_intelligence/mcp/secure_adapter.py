from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from agentic_threat_intelligence.security.audit import (
    NullSecurityAuditSink,
    SecurityAuditEvent,
    SecurityAuditSink,
)
from agentic_threat_intelligence.security.identity import SecurityPrincipal
from agentic_threat_intelligence.security.tool_authorization import (
    ToolAuthorizationPolicy,
)

from .adapter import MCPToolAdapter


class ToolAuthorizationError(PermissionError):
    pass


@dataclass
class SecuredMCPToolAdapter:
    """Secure facade around the raw MCP transport adapter."""

    transport: MCPToolAdapter
    authorizer: ToolAuthorizationPolicy
    audit_sink: SecurityAuditSink = field(
        default_factory=NullSecurityAuditSink
    )

    async def invoke(
        self,
        *,
        principal: SecurityPrincipal,
        case_id: str,
        trace_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        human_approved: bool = False,
    ) -> Mapping[str, Any]:
        decision = self.authorizer.authorize(
            principal=principal,
            tool_name=tool_name,
            arguments=arguments,
            human_approved=human_approved,
        )

        await self.audit_sink.write(
            SecurityAuditEvent.create(
                event_type="MCP_TOOL_AUTHORIZATION",
                principal_id=principal.subject_id,
                action="invoke",
                resource=tool_name,
                allowed=decision.allowed,
                reason=decision.reason,
                case_id=case_id,
                trace_id=trace_id,
            )
        )

        if not decision.allowed:
            raise ToolAuthorizationError(
                f"Tool call denied for {principal.subject_id}: "
                f"{tool_name} ({decision.reason})"
            )

        try:
            result = await self.transport.invoke(
                tool_name=tool_name,
                arguments=arguments,
            )
        except Exception as exc:
            await self.audit_sink.write(
                SecurityAuditEvent.create(
                    event_type="MCP_TOOL_EXECUTION",
                    principal_id=principal.subject_id,
                    action="invoke",
                    resource=tool_name,
                    allowed=False,
                    reason=f"execution_failed:{type(exc).__name__}",
                    case_id=case_id,
                    trace_id=trace_id,
                )
            )
            raise

        await self.audit_sink.write(
            SecurityAuditEvent.create(
                event_type="MCP_TOOL_EXECUTION",
                principal_id=principal.subject_id,
                action="invoke",
                resource=tool_name,
                allowed=True,
                reason="execution_succeeded",
                case_id=case_id,
                trace_id=trace_id,
            )
        )
        return result
