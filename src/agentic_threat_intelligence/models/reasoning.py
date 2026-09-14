from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class ModelRequest:
    system_instruction: str
    user_content: str
    response_schema_name: str
    trace_id: str

@dataclass(frozen=True)
class ModelResponse:
    text: str
    model_name: str
    provider: str
    latency_ms: float

class ReasoningModel(Protocol):
    async def complete(self, request: ModelRequest) -> ModelResponse: ...
