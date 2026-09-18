from __future__ import annotations

from dataclasses import dataclass, field

from agentic_threat_intelligence.communication.contracts import AgentResult
from agentic_threat_intelligence.policy.engine import FinalDisposition


@dataclass(frozen=True)
class DeterministicEvidence:
    """Trusted deterministic evidence supplied to agentic decision stages."""

    risk_score: float
    strong_signal_count: int
    ml_label: str | None = None
    ml_confidence: float | None = None
    security_signals: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not 0.0 <= self.risk_score <= 100.0:
            raise ValueError("risk_score must be between 0 and 100")
        if self.strong_signal_count < 0:
            raise ValueError("strong_signal_count must be >= 0")
        if self.ml_confidence is not None and not (
            0.0 <= self.ml_confidence <= 1.0
        ):
            raise ValueError("ml_confidence must be between 0 and 1")


@dataclass(frozen=True)
class FinalTriageDecision:
    """Complete decision artifact returned by the orchestration facade."""

    final_disposition: FinalDisposition
    policy_reason: str
    human_review_required: bool
    message_intelligence: AgentResult
    threat_intelligence: AgentResult | None
    risk_triage: AgentResult
    policy_response: AgentResult
    explainability: AgentResult
