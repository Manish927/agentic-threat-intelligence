from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping

@dataclass(frozen=True)
class AgentContext:
    case_id: str
    trace_id: str
    deadline_epoch_ms: int | None
    attributes: Mapping[str, Any]

class SpecializedAgent(ABC):
    name: str
    version: str
    @abstractmethod
    async def handle(self, task: Any, context: AgentContext) -> Any: ...
