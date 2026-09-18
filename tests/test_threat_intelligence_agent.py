import pytest

from agentic_threat_intelligence.agents.base import AgentContext
from agentic_threat_intelligence.agents.threat_intelligence import (
    ThreatIntelligenceAgent,
    ThreatIntelligenceTask,
)
from agentic_threat_intelligence.mcp.adapter import MCPToolAdapter
from agentic_threat_intelligence.mcp.secure_adapter import (
    SecuredMCPToolAdapter,
    ToolAuthorizationError,
)
from agentic_threat_intelligence.security.audit import (
    InMemorySecurityAuditSink,
)
from agentic_threat_intelligence.security.default_policies import (
    THREAT_INTEL_AGENT_SUBJECT,
    THREAT_INTEL_READ_SCOPE,
    build_threat_intelligence_tool_policy,
)
from agentic_threat_intelligence.security.identity import (
    PrincipalType,
    SecurityPrincipal,
)


class RecordingThreatIntelClient:
    def __init__(self) -> None:
        self.calls = []

    async def call_tool(self, tool_name, arguments):
        self.calls.append((tool_name, dict(arguments)))
        value = next(iter(arguments.values()))
        return {
            "verdict": (
                "malicious"
                if "evil" in value
                else "suspicious"
            ),
            "confidence": 0.93,
            "provider": "offline-test-provider",
        }


class InvalidThreatIntelClient:
    async def call_tool(self, tool_name, arguments):
        return {
            "verdict": "definitely-bad",
            "confidence": 0.9,
            "provider": "broken-provider",
        }


def _principal(*, with_scope=True):
    return SecurityPrincipal(
        subject_id=THREAT_INTEL_AGENT_SUBJECT,
        principal_type=PrincipalType.AGENT,
        scopes=(
            frozenset({THREAT_INTEL_READ_SCOPE})
            if with_scope
            else frozenset()
        ),
    )


def _context():
    return AgentContext(
        case_id="case-ti-1",
        trace_id="trace-ti-1",
        deadline_epoch_ms=None,
        attributes={},
    )


def _secured_adapter(client, audit_sink=None):
    return SecuredMCPToolAdapter(
        transport=MCPToolAdapter(client=client),
        authorizer=build_threat_intelligence_tool_policy(),
        audit_sink=audit_sink or InMemorySecurityAuditSink(),
    )


@pytest.mark.asyncio
async def test_authorized_indicator_lookups_use_secured_mcp_and_audit():
    client = RecordingThreatIntelClient()
    audit = InMemorySecurityAuditSink()
    agent = ThreatIntelligenceAgent(
        mcp=_secured_adapter(client, audit),
        principal=_principal(),
    )

    result = await agent.handle(
        ThreatIntelligenceTask(
            urls=("https://evil.example/login",),
            domains=("suspicious.example",),
        ),
        _context(),
    )

    assert result.task == "indicator.enrich"
    assert len(result.findings) == 2
    assert result.attributes["lookup_count"] == 2
    assert result.attributes["providers"] == (
        "offline-test-provider",
    )
    assert len(client.calls) == 2

    # Authorization + execution event for each lookup.
    assert len(audit.events) == 4
    assert all(event.allowed for event in audit.events)


@pytest.mark.asyncio
async def test_missing_scope_fails_closed_before_mcp_execution():
    client = RecordingThreatIntelClient()
    agent = ThreatIntelligenceAgent(
        mcp=_secured_adapter(client),
        principal=_principal(with_scope=False),
    )

    with pytest.raises(ToolAuthorizationError):
        await agent.handle(
            ThreatIntelligenceTask(
                domains=("suspicious.example",),
            ),
            _context(),
        )

    assert client.calls == []


@pytest.mark.asyncio
async def test_invalid_external_result_is_not_promoted_to_evidence():
    agent = ThreatIntelligenceAgent(
        mcp=_secured_adapter(InvalidThreatIntelClient()),
        principal=_principal(),
    )

    result = await agent.handle(
        ThreatIntelligenceTask(
            urls=("https://example.invalid",),
        ),
        _context(),
    )

    assert result.findings == ()
    assert len(result.attributes["errors"]) == 1
    assert "invalid_tool_result" in result.attributes["errors"][0]


@pytest.mark.asyncio
async def test_empty_indicator_set_skips_tool_calls():
    client = RecordingThreatIntelClient()
    agent = ThreatIntelligenceAgent(
        mcp=_secured_adapter(client),
        principal=_principal(),
    )

    result = await agent.handle(
        ThreatIntelligenceTask(),
        _context(),
    )

    assert result.findings == ()
    assert result.attributes["skipped"] is True
    assert client.calls == []


def test_threat_intelligence_requires_agent_identity():
    with pytest.raises(
        ValueError,
        match="requires an AGENT principal",
    ):
        ThreatIntelligenceAgent(
            mcp=_secured_adapter(RecordingThreatIntelClient()),
            principal=SecurityPrincipal(
                subject_id="user:analyst",
                principal_type=PrincipalType.USER,
                scopes=frozenset({THREAT_INTEL_READ_SCOPE}),
            ),
        )
