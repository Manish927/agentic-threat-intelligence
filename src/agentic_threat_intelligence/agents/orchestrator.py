from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Iterable

from agentic_threat_intelligence.agents.base import AgentContext, SpecializedAgent
from agentic_threat_intelligence.agents.message_intelligence import MessageIntelligenceTask
from agentic_threat_intelligence.agents.threat_intelligence import ThreatIntelligenceTask
from agentic_threat_intelligence.communication.contracts import AgentResult
from agentic_threat_intelligence.decision.models import DeterministicEvidence, FinalTriageDecision
from agentic_threat_intelligence.workflows.decision import DecisionWorkflow
from agentic_threat_intelligence.workflows.message_intelligence import MessageIntelligenceWorkflow
from agentic_threat_intelligence.workflows.triage import TriageWorkflow, TriageWorkflowResult


@dataclass(frozen=True)
class PlannedInvocation:
    agent: SpecializedAgent
    task: Any


class TriageOrchestrator:
    """Stable application facade over LangGraph workflows."""

    def __init__(
        self,
        *,
        message_intelligence_workflow: MessageIntelligenceWorkflow | None = None,
        triage_workflow: TriageWorkflow | None = None,
        decision_workflow: DecisionWorkflow | None = None,
    ) -> None:
        self._message_intelligence_workflow=message_intelligence_workflow
        self._triage_workflow=triage_workflow
        self._decision_workflow=decision_workflow

    async def execute_parallel(self, invocations: Iterable[PlannedInvocation], context: AgentContext) -> list[Any]:
        return list(await asyncio.gather(*(x.agent.handle(x.task, context) for x in invocations)))

    async def analyze_message(self, *, task: MessageIntelligenceTask, context: AgentContext) -> AgentResult:
        if self._message_intelligence_workflow is None:
            raise RuntimeError("Message Intelligence workflow is not configured")
        return await self._message_intelligence_workflow.run(task=task, context=context)

    async def analyze_case(
        self,
        *,
        message_task: MessageIntelligenceTask,
        threat_task: ThreatIntelligenceTask,
        context: AgentContext,
    ) -> TriageWorkflowResult:
        if self._triage_workflow is None:
            raise RuntimeError("Triage workflow is not configured")
        return await self._triage_workflow.run(
            message_task=message_task,
            threat_task=threat_task,
            context=context,
        )

    async def decide_case(
        self,
        *,
        message_task: MessageIntelligenceTask,
        threat_task: ThreatIntelligenceTask,
        deterministic_evidence: DeterministicEvidence,
        context: AgentContext,
    ) -> FinalTriageDecision:
        if self._decision_workflow is None:
            raise RuntimeError("Decision workflow is not configured")
        return await self._decision_workflow.run(
            message_task=message_task,
            threat_task=threat_task,
            deterministic_evidence=deterministic_evidence,
            context=context,
        )
