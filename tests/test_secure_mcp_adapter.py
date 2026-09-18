import pytest

from agentic_threat_intelligence.mcp.adapter import MCPToolAdapter
from agentic_threat_intelligence.mcp.secure_adapter import (
    SecuredMCPToolAdapter,
    ToolAuthorizationError,
)
from agentic_threat_intelligence.security.audit import (
    InMemorySecurityAuditSink,
)
from agentic_threat_intelligence.security.identity import (
    PrincipalType,
    SecurityPrincipal,
)
from agentic_threat_intelligence.security.tool_authorization import (
    ToolAccessRule,
    ToolAuthorizationPolicy,
)


class FakeMCPClient:
    def __init__(self):
        self.calls = []

    async def call_tool(self, tool_name, arguments):
        self.calls.append((tool_name, dict(arguments)))
        return {"status": "ok"}


@pytest.mark.asyncio
async def test_secure_mcp_adapter_authorizes_and_audits():
    client = FakeMCPClient()
    audit = InMemorySecurityAuditSink()

    secured = SecuredMCPToolAdapter(
        transport=MCPToolAdapter(client),
        authorizer=ToolAuthorizationPolicy(
            [
                ToolAccessRule(
                    name="vt-read",
                    tool_pattern="virustotal.lookup_url",
                    allowed_subject_patterns=frozenset(
                        {"agent:threat-intelligence"}
                    ),
                    required_scopes=frozenset({"threatintel.read"}),
                    allowed_argument_keys=frozenset({"url"}),
                )
            ]
        ),
        audit_sink=audit,
    )

    result = await secured.invoke(
        principal=SecurityPrincipal(
            subject_id="agent:threat-intelligence",
            principal_type=PrincipalType.AGENT,
            scopes=frozenset({"threatintel.read"}),
        ),
        case_id="case-1",
        trace_id="trace-1",
        tool_name="virustotal.lookup_url",
        arguments={"url": "https://example.test"},
    )

    assert result == {"status": "ok"}
    assert client.calls == [
        ("virustotal.lookup_url", {"url": "https://example.test"})
    ]
    assert len(audit.events) == 2
    assert audit.events[0].event_type == "MCP_TOOL_AUTHORIZATION"
    assert audit.events[0].allowed is True


@pytest.mark.asyncio
async def test_secure_mcp_adapter_blocks_before_transport():
    client = FakeMCPClient()
    audit = InMemorySecurityAuditSink()

    secured = SecuredMCPToolAdapter(
        transport=MCPToolAdapter(client),
        authorizer=ToolAuthorizationPolicy([]),
        audit_sink=audit,
    )

    with pytest.raises(ToolAuthorizationError):
        await secured.invoke(
            principal=SecurityPrincipal(
                subject_id="agent:message-intelligence",
                principal_type=PrincipalType.AGENT,
            ),
            case_id="case-1",
            trace_id="trace-1",
            tool_name="mail.delete",
            arguments={"message_id": "m-1"},
        )

    assert client.calls == []
    assert len(audit.events) == 1
    assert audit.events[0].allowed is False
