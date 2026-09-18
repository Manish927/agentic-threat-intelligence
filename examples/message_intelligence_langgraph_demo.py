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
from agentic_threat_intelligence.models.reasoning import ModelResponse
from agentic_threat_intelligence.workflows.message_intelligence import (
    MessageIntelligenceWorkflow,
)


class DemoReasoningModel:
    """Offline demo provider.

    Replace this with a Gemini/Vertex/Bedrock/OpenAI adapter implementing
    ReasoningModel. The workflow and agent do not change.
    """

    async def complete(self, request):
        return ModelResponse(
            text=json.dumps(
                {
                    "intent": "Credential theft",
                    "summary": (
                        "The email impersonates an account-security notice "
                        "and pressures the recipient to verify credentials."
                    ),
                    "confidence": 0.96,
                    "signals": [
                        {
                            "type": "urgency",
                            "summary": (
                                "The recipient is told the account will be "
                                "suspended immediately."
                            ),
                            "confidence": 0.97,
                        },
                        {
                            "type": "social_engineering",
                            "summary": (
                                "The email attempts to induce a credential "
                                "verification action."
                            ),
                            "confidence": 0.95,
                        },
                    ],
                    "recommended_follow_up": ["indicator.enrich"],
                }
            ),
            model_name="offline-demo",
            provider="demo",
            latency_ms=0.0,
        )


async def main():
    agent = MessageIntelligenceAgent(model=DemoReasoningModel())
    workflow = MessageIntelligenceWorkflow(agent)
    orchestrator = TriageOrchestrator(
        message_intelligence_workflow=workflow
    )

    result = await orchestrator.analyze_message(
        task=MessageIntelligenceTask(
            subject="URGENT: Your Microsoft 365 account will be suspended",
            sanitized_body=(
                "We detected unusual sign-in activity. Verify your identity "
                "within two hours to prevent account suspension."
            ),
            sender=(
                "Microsoft Security "
                "<security-alert@microsoft-account-verify.example>"
            ),
            language_features={"urgency": True, "suspension": True},
        ),
        context=AgentContext(
            case_id="demo-case-1",
            trace_id="demo-trace-1",
            deadline_epoch_ms=None,
            attributes={},
        ),
    )

    print("Intent:", result.attributes["intent"])
    print("Confidence:", result.confidence)
    for finding in result.findings:
        print(
            f"- {finding.finding_type}: "
            f"{finding.summary} ({finding.confidence:.2f})"
        )


if __name__ == "__main__":
    asyncio.run(main())
