import pytest
from agentic_threat_intelligence.agents.base import AgentContext, SpecializedAgent
from agentic_threat_intelligence.agents.orchestrator import PlannedInvocation, TriageOrchestrator

class EchoAgent(SpecializedAgent):
    name = "echo"
    version = "1.0"
    async def handle(self, task, context):
        return {"task": task, "case_id": context.case_id}

@pytest.mark.asyncio
async def test_orchestrator_executes_specialists():
    orchestrator = TriageOrchestrator()
    context = AgentContext(case_id="case-1", trace_id="trace-1", deadline_epoch_ms=None, attributes={})
    results = await orchestrator.execute_parallel(
        [PlannedInvocation(agent=EchoAgent(), task="analyze")], context
    )
    assert results == [{"task": "analyze", "case_id": "case-1"}]
