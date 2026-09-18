from __future__ import annotations

from dataclasses import dataclass
from typing import NotRequired, TypedDict

from langgraph.graph import END, START, StateGraph

from agentic_threat_intelligence.agents.base import AgentContext
from agentic_threat_intelligence.agents.message_intelligence import (
    MessageIntelligenceAgent,
    MessageIntelligenceTask,
)
from agentic_threat_intelligence.agents.threat_intelligence import (
    ThreatIntelligenceAgent,
    ThreatIntelligenceTask,
)
from agentic_threat_intelligence.communication.contracts import (
    AgentResult,
)


class TriageWorkflowState(TypedDict):
    message_task: MessageIntelligenceTask
    threat_task: ThreatIntelligenceTask
    context: AgentContext
    message_result: NotRequired[AgentResult]
    threat_result: NotRequired[AgentResult | None]


@dataclass(frozen=True)
class TriageWorkflowResult:
    message_intelligence: AgentResult
    threat_intelligence: AgentResult | None


class TriageWorkflow:
    """Parallel LangGraph fan-out for independent specialist analysis.

    Message semantics and indicator reputation do not depend on one another,
    so they execute in parallel. A later foundation will join these results
    into Risk / Triage.
    """

    def __init__(
        self,
        *,
        message_intelligence_agent: MessageIntelligenceAgent,
        threat_intelligence_agent: ThreatIntelligenceAgent,
    ) -> None:
        self._message_intelligence_agent = message_intelligence_agent
        self._threat_intelligence_agent = threat_intelligence_agent

        builder = StateGraph(TriageWorkflowState)
        builder.add_node(
            "message_intelligence",
            self._message_intelligence_node,
        )
        builder.add_node(
            "threat_intelligence",
            self._threat_intelligence_node,
        )
        builder.add_node(
            "evidence_join",
            self._evidence_join_node,
        )

        # Independent specialists fan out in parallel.
        builder.add_edge(START, "message_intelligence")
        builder.add_edge(START, "threat_intelligence")

        # Join only after both branches complete.
        builder.add_edge(
            ["message_intelligence", "threat_intelligence"],
            "evidence_join",
        )
        builder.add_edge("evidence_join", END)

        # No in-memory checkpointer is configured. Durable shared state for
        # human-in-the-loop workflows will use an external production store.
        self._graph = builder.compile()

    async def _message_intelligence_node(
        self,
        state: TriageWorkflowState,
    ) -> dict[str, AgentResult]:
        return {
            "message_result": (
                await self._message_intelligence_agent.handle(
                    state["message_task"],
                    state["context"],
                )
            )
        }

    async def _threat_intelligence_node(
        self,
        state: TriageWorkflowState,
    ) -> dict[str, AgentResult | None]:
        if not state["threat_task"].has_indicators():
            return {"threat_result": None}

        return {
            "threat_result": (
                await self._threat_intelligence_agent.handle(
                    state["threat_task"],
                    state["context"],
                )
            )
        }

    async def _evidence_join_node(
        self,
        state: TriageWorkflowState,
    ) -> dict:
        # This node deliberately does not reinterpret evidence. Its purpose
        # is to create an explicit synchronization point for the future
        # Risk / Triage stage.
        return {}

    async def run(
        self,
        *,
        message_task: MessageIntelligenceTask,
        threat_task: ThreatIntelligenceTask,
        context: AgentContext,
    ) -> TriageWorkflowResult:
        output = await self._graph.ainvoke(
            {
                "message_task": message_task,
                "threat_task": threat_task,
                "context": context,
            }
        )

        message_result = output.get("message_result")
        if not isinstance(message_result, AgentResult):
            raise RuntimeError(
                "Triage workflow completed without Message Intelligence"
            )

        threat_result = output.get("threat_result")
        if threat_result is not None and not isinstance(
            threat_result,
            AgentResult,
        ):
            raise RuntimeError(
                "Triage workflow produced invalid Threat Intelligence"
            )

        return TriageWorkflowResult(
            message_intelligence=message_result,
            threat_intelligence=threat_result,
        )
