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
from agentic_threat_intelligence.models.reasoning import ModelResponse
from agentic_threat_intelligence.workflows.message_intelligence import (
    MessageIntelligenceWorkflow,
)


class WorkflowTestModel:
    async def complete(self, request):
        return ModelResponse(
            text=json.dumps(
                {
                    "intent": "Social engineering",
                    "summary": "Urgent verification request.",
                    "confidence": 0.91,
                    "signals": [
                        {
                            "type": "social_engineering",
                            "summary": "The recipient is pressured to take action.",
                            "confidence": 0.92,
                        }
                    ],
                    "recommended_follow_up": ["indicator.enrich"],
                }
            ),
            model_name="workflow-test-model",
            provider="test",
            latency_ms=3.0,
        )


@pytest.mark.asyncio
async def test_langgraph_workflow_executes_message_intelligence():
    agent = MessageIntelligenceAgent(model=WorkflowTestModel())
    workflow = MessageIntelligenceWorkflow(agent)

    result = await workflow.run(
        task=MessageIntelligenceTask(
            subject="Verify now",
            sanitized_body="Your account will be suspended.",
            sender="security@example.invalid",
        ),
        context=AgentContext(
            case_id="case-lg-1",
            trace_id="trace-lg-1",
            deadline_epoch_ms=None,
            attributes={},
        ),
    )

    assert result.task == "message.analyze"
    assert result.confidence == pytest.approx(0.91)
    assert result.findings[0].finding_type == "social_engineering"


@pytest.mark.asyncio
async def test_triage_orchestrator_is_facade_over_langgraph_workflow():
    agent = MessageIntelligenceAgent(model=WorkflowTestModel())
    workflow = MessageIntelligenceWorkflow(agent)
    orchestrator = TriageOrchestrator(
        message_intelligence_workflow=workflow
    )

    result = await orchestrator.analyze_message(
        task=MessageIntelligenceTask(
            subject="Verify now",
            sanitized_body="Your account will be suspended.",
            sender="security@example.invalid",
        ),
        context=AgentContext(
            case_id="case-lg-2",
            trace_id="trace-lg-2",
            deadline_epoch_ms=None,
            attributes={},
        ),
    )

    assert result.attributes["intent"] == "Social engineering"


@pytest.mark.asyncio
async def test_orchestrator_requires_configured_workflow():
    orchestrator = TriageOrchestrator()

    with pytest.raises(
        RuntimeError,
        match="workflow is not configured",
    ):
        await orchestrator.analyze_message(
            task=MessageIntelligenceTask(
                subject="x",
                sanitized_body="y",
                sender="z",
            ),
            context=AgentContext(
                case_id="case-lg-3",
                trace_id="trace-lg-3",
                deadline_epoch_ms=None,
                attributes={},
            ),
        )
