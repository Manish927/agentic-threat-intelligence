import json

import pytest

from agentic_threat_intelligence.agents.base import AgentContext
from agentic_threat_intelligence.agents.message_intelligence import (
    MessageIntelligenceAgent,
    MessageIntelligenceTask,
)
from agentic_threat_intelligence.agents.orchestrator import (
    TriageOrchestrator,
)
from agentic_threat_intelligence.agents.threat_intelligence import (
    ThreatIntelligenceAgent,
    ThreatIntelligenceTask,
)
from agentic_threat_intelligence.mcp.adapter import MCPToolAdapter
from agentic_threat_intelligence.mcp.secure_adapter import (
    SecuredMCPToolAdapter,
)
from agentic_threat_intelligence.models.reasoning import ModelResponse
from agentic_threat_intelligence.security.default_policies import (
    THREAT_INTEL_AGENT_SUBJECT,
    THREAT_INTEL_READ_SCOPE,
    build_threat_intelligence_tool_policy,
)
from agentic_threat_intelligence.security.identity import (
    PrincipalType,
    SecurityPrincipal,
)
from agentic_threat_intelligence.workflows.triage import (
    TriageWorkflow,
)


class TriageModel:
    async def complete(self, request):
        return ModelResponse(
            text=json.dumps(
                {
                    "intent": "Credential theft",
                    "summary": "Credential verification pressure.",
                    "confidence": 0.95,
                    "signals": [
                        {
                            "type": "urgency",
                            "summary": "Immediate suspension is threatened.",
                            "confidence": 0.96,
                        }
                    ],
                    "recommended_follow_up": [
                        "indicator.enrich"
                    ],
                }
            ),
            model_name="triage-test-model",
            provider="test",
            latency_ms=1.0,
        )


class TriageThreatIntelClient:
    def __init__(self):
        self.calls = []

    async def call_tool(self, tool_name, arguments):
        self.calls.append((tool_name, dict(arguments)))
        return {
            "verdict": "malicious",
            "confidence": 0.98,
            "provider": "test-intel",
        }


def _build(client):
    message_agent = MessageIntelligenceAgent(model=TriageModel())

    secured_mcp = SecuredMCPToolAdapter(
        transport=MCPToolAdapter(client=client),
        authorizer=build_threat_intelligence_tool_policy(),
    )

    threat_agent = ThreatIntelligenceAgent(
        mcp=secured_mcp,
        principal=SecurityPrincipal(
            subject_id=THREAT_INTEL_AGENT_SUBJECT,
            principal_type=PrincipalType.AGENT,
            scopes=frozenset({THREAT_INTEL_READ_SCOPE}),
        ),
    )

    workflow = TriageWorkflow(
        message_intelligence_agent=message_agent,
        threat_intelligence_agent=threat_agent,
    )
    return TriageOrchestrator(triage_workflow=workflow)


def _context():
    return AgentContext(
        case_id="case-triage-1",
        trace_id="trace-triage-1",
        deadline_epoch_ms=None,
        attributes={},
    )


@pytest.mark.asyncio
async def test_triage_workflow_joins_message_and_threat_intelligence():
    client = TriageThreatIntelClient()
    orchestrator = _build(client)

    result = await orchestrator.analyze_case(
        message_task=MessageIntelligenceTask(
            subject="URGENT account suspension",
            sanitized_body="Verify credentials immediately.",
            sender="security@example.invalid",
        ),
        threat_task=ThreatIntelligenceTask(
            urls=("https://evil.example/login",),
        ),
        context=_context(),
    )

    assert result.message_intelligence.attributes["intent"] == (
        "Credential theft"
    )
    assert result.threat_intelligence is not None
    assert (
        result.threat_intelligence.findings[0].finding_type
        == "threat_intel_malicious"
    )
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_triage_workflow_skips_threat_branch_without_indicators():
    client = TriageThreatIntelClient()
    orchestrator = _build(client)

    result = await orchestrator.analyze_case(
        message_task=MessageIntelligenceTask(
            subject="Team meeting",
            sanitized_body="Meeting moved to Thursday.",
            sender="colleague@example.com",
        ),
        threat_task=ThreatIntelligenceTask(),
        context=_context(),
    )

    assert result.message_intelligence is not None
    assert result.threat_intelligence is None
    assert client.calls == []


@pytest.mark.asyncio
async def test_orchestrator_requires_triage_workflow():
    orchestrator = TriageOrchestrator()

    with pytest.raises(
        RuntimeError,
        match="Triage workflow is not configured",
    ):
        await orchestrator.analyze_case(
            message_task=MessageIntelligenceTask(
                subject="x",
                sanitized_body="y",
                sender="z",
            ),
            threat_task=ThreatIntelligenceTask(),
            context=_context(),
        )
