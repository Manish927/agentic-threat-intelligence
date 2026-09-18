from __future__ import annotations

from typing import NotRequired, TypedDict

from langgraph.graph import END, START, StateGraph

from agentic_threat_intelligence.agents.base import AgentContext
from agentic_threat_intelligence.agents.message_intelligence import (
    MessageIntelligenceAgent,
    MessageIntelligenceTask,
)
from agentic_threat_intelligence.communication.contracts import AgentResult


class MessageIntelligenceState(TypedDict):
    """Per-invocation LangGraph state.

    No state is stored globally. This keeps the workflow safe for concurrent
    use by many users/workers. Durable persistence can later be supplied by an
    external production checkpointer.
    """

    task: MessageIntelligenceTask
    context: AgentContext
    result: NotRequired[AgentResult]


class MessageIntelligenceWorkflow:
    """LangGraph workflow for the first specialized agent."""

    def __init__(self, agent: MessageIntelligenceAgent) -> None:
        self._agent = agent

        builder = StateGraph(MessageIntelligenceState)
        builder.add_node(
            "message_intelligence",
            self._message_intelligence_node,
        )
        builder.add_edge(START, "message_intelligence")
        builder.add_edge("message_intelligence", END)

        # Compile once and reuse. The compiled graph is stateless between
        # invocations because no in-memory checkpointer is configured.
        self._graph = builder.compile()

    async def _message_intelligence_node(
        self,
        state: MessageIntelligenceState,
    ) -> dict[str, AgentResult]:
        result = await self._agent.handle(
            state["task"],
            state["context"],
        )
        return {"result": result}

    async def run(
        self,
        *,
        task: MessageIntelligenceTask,
        context: AgentContext,
    ) -> AgentResult:
        output = await self._graph.ainvoke(
            {
                "task": task,
                "context": context,
            }
        )

        result = output.get("result")
        if not isinstance(result, AgentResult):
            raise RuntimeError(
                "Message Intelligence workflow completed without "
                "a valid AgentResult"
            )
        return result
