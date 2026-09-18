from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Iterable

from agentic_threat_intelligence.agents.base import (
    AgentContext,
    SpecializedAgent,
)
from agentic_threat_intelligence.agents.message_intelligence import (
    MessageIntelligenceTask,
)
from agentic_threat_intelligence.communication.contracts import AgentResult
from agentic_threat_intelligence.workflows.message_intelligence import (
    MessageIntelligenceWorkflow,
)


@dataclass(frozen=True)
class PlannedInvocation:
    agent: SpecializedAgent
    task: Any


class TriageOrchestrator:
    """Public orchestration facade.

    LangGraph is an implementation detail behind workflow objects. The
    orchestrator remains the stable application-facing API so the security,
    API, and cloud deployment layers do not depend directly on LangGraph.
    """

    def __init__(
        self,
        *,
        message_intelligence_workflow: MessageIntelligenceWorkflow | None = None,
    ) -> None:
        self._message_intelligence_workflow = (
            message_intelligence_workflow
        )

    async def execute_parallel(
        self,
        invocations: Iterable[PlannedInvocation],
        context: AgentContext,
    ) -> list[Any]:
        """Compatibility path for independent specialist invocations.

        This remains useful for tests and simple fan-out. Stateful production
        triage flows should be expressed as LangGraph workflows.
        """

        return list(
            await asyncio.gather(
                *(
                    invocation.agent.handle(invocation.task, context)
                    for invocation in invocations
                )
            )
        )

    async def analyze_message(
        self,
        *,
        task: MessageIntelligenceTask,
        context: AgentContext,
    ) -> AgentResult:
        """Execute Message Intelligence through the LangGraph workflow."""

        if self._message_intelligence_workflow is None:
            raise RuntimeError(
                "Message Intelligence workflow is not configured"
            )

        return await self._message_intelligence_workflow.run(
            task=task,
            context=context,
        )
