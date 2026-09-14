from dataclasses import dataclass
from enum import StrEnum

class FinalDisposition(StrEnum):
    ALLOW='ALLOW'; MONITOR='MONITOR'; QUARANTINE='QUARANTINE'; HUMAN_REVIEW='HUMAN_REVIEW'

@dataclass(frozen=True)
class PolicyInput:
    deterministic_risk_score: float
    strong_signal_count: int
    agent_recommendation: str | None
    agent_confidence: float | None

class DeterministicPolicyEngine:
    def decide(self, x: PolicyInput) -> FinalDisposition:
        if x.deterministic_risk_score >= 90 or x.strong_signal_count >= 4: return FinalDisposition.HUMAN_REVIEW
        if x.deterministic_risk_score >= 70: return FinalDisposition.QUARANTINE
        if x.deterministic_risk_score >= 40: return FinalDisposition.MONITOR
        return FinalDisposition.ALLOW
