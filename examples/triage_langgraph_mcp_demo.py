from __future__ import annotations

import asyncio
import json

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
from agentic_threat_intelligence.workflows.triage import TriageWorkflow


class DemoReasoningModel:
    async def complete(self, request):
        return ModelResponse(
            text=json.dumps(
                {
                    "intent": "Credential theft",
                    "summary": (
                        "The email impersonates a security notice and "
                        "pressures the recipient to verify credentials."
                    ),
                    "confidence": 0.96,
                    "signals": [
                        {
                            "type": "urgency",
                            "summary": (
                                "The account is threatened with immediate "
                                "suspension."
                            ),
                            "confidence": 0.97,
                        },
                        {
                            "type": "impersonation",
                            "summary": (
                                "The sender claims to represent Microsoft "
                                "security."
                            ),
                            "confidence": 0.94,
                        },
                    ],
                    "recommended_follow_up": ["indicator.enrich"],
                }
            ),
            model_name="offline-message-demo",
            provider="demo",
            latency_ms=0.0,
        )


class DemoThreatIntelMCPClient:
    """Offline MCP client standing in for an approved MCP server."""

    async def call_tool(self, tool_name, arguments):
        indicator = next(iter(arguments.values()))
        malicious = (
            "microsoft-account-verify" in indicator
            or ".xyz" in indicator
        )
        return {
            "verdict": "malicious" if malicious else "unknown",
            "confidence": 0.98 if malicious else 0.50,
            "provider": "offline-threat-intel-demo",
        }


async def main():
    message_agent = MessageIntelligenceAgent(
        model=DemoReasoningModel()
    )

    audit = InMemorySecurityAuditSink()
    secured_mcp = SecuredMCPToolAdapter(
        transport=MCPToolAdapter(
            client=DemoThreatIntelMCPClient()
        ),
        authorizer=build_threat_intelligence_tool_policy(),
        audit_sink=audit,
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
    orchestrator = TriageOrchestrator(
        triage_workflow=workflow
    )

    result = await orchestrator.analyze_case(
        message_task=MessageIntelligenceTask(
            subject=(
                "URGENT: Your Microsoft 365 account will be suspended"
            ),
            sanitized_body=(
                "We detected unusual sign-in activity. Verify your "
                "identity within two hours."
            ),
            sender=(
                "Microsoft Security "
                "<security-alert@microsoft-account-verify.com>"
            ),
            language_features={
                "urgency": True,
                "suspension": True,
            },
        ),
        threat_task=ThreatIntelligenceTask(
            urls=(
                "https://microsoft-account-verify.xyz/"
                "account/verify-credentials",
            ),
            domains=("microsoft-account-verify.xyz",),
        ),
        context=AgentContext(
            case_id="demo-case-2",
            trace_id="demo-trace-2",
            deadline_epoch_ms=None,
            attributes={},
        ),
    )

    print(
        "Message intent:",
        result.message_intelligence.attributes["intent"],
    )
    print(
        "Message confidence:",
        result.message_intelligence.confidence,
    )

    if result.threat_intelligence:
        for finding in result.threat_intelligence.findings:
            print(
                f"Threat intel: {finding.summary} "
                f"({finding.confidence:.2f})"
            )

    print("Security audit events:", len(audit.events))


if __name__ == "__main__":
    asyncio.run(main())
