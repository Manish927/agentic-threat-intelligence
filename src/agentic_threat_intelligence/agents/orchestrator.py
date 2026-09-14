import asyncio
from dataclasses import dataclass
from typing import Any, Iterable
from .base import AgentContext, SpecializedAgent

@dataclass(frozen=True)
class PlannedInvocation:
    agent: SpecializedAgent
    task: Any

class TriageOrchestrator:
    async def execute_parallel(self, invocations: Iterable[PlannedInvocation], context: AgentContext) -> list[Any]:
        return list(await asyncio.gather(*(x.agent.handle(x.task, context) for x in invocations)))
