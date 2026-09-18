from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FinalDisposition(StrEnum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    QUARANTINE = "QUARANTINE"
    HUMAN_REVIEW = "HUMAN_REVIEW"


@dataclass(frozen=True)
class PolicyInput:
    deterministic_risk_score: float
    strong_signal_count: int
    agent_recommendation: str | None
    agent_confidence: float | None


@dataclass(frozen=True)
class PolicyDecision:
    disposition: FinalDisposition
    reason_code: str
    agent_escalation_applied: bool = False


class DeterministicPolicyEngine:
    """Deterministic final authority.

    Agent recommendations may increase scrutiny under explicit confidence
    thresholds, but they can never downgrade deterministic controls and cannot
    directly authorize a destructive quarantine from a low-risk baseline.
    """

    def decide(self, x: PolicyInput) -> FinalDisposition:
        return self.evaluate(x).disposition

    def evaluate(self, x: PolicyInput) -> PolicyDecision:
        self._validate(x)
        base = self._baseline(x)

        recommendation = self._recommendation(x.agent_recommendation)
        confidence = x.agent_confidence
        if recommendation is None or confidence is None:
            return base

        # Never permit an agent to downgrade an existing deterministic result.
        if base.disposition is FinalDisposition.HUMAN_REVIEW:
            return base

        if recommendation is FinalDisposition.HUMAN_REVIEW and confidence >= 0.85:
            return PolicyDecision(
                FinalDisposition.HUMAN_REVIEW,
                "agent_human_review_escalation",
                True,
            )

        # An agent can flag quarantine-worthy evidence, but low/medium
        # deterministic risk is escalated to a human rather than allowing the
        # model to authorize a destructive action.
        if (
            recommendation is FinalDisposition.QUARANTINE
            and confidence >= 0.90
            and base.disposition in {FinalDisposition.ALLOW, FinalDisposition.MONITOR}
        ):
            return PolicyDecision(
                FinalDisposition.HUMAN_REVIEW,
                "agent_quarantine_requires_human_review",
                True,
            )

        if (
            recommendation is FinalDisposition.MONITOR
            and confidence >= 0.80
            and base.disposition is FinalDisposition.ALLOW
        ):
            return PolicyDecision(
                FinalDisposition.MONITOR,
                "agent_monitor_escalation",
                True,
            )

        return base

    @staticmethod
    def _baseline(x: PolicyInput) -> PolicyDecision:
        if x.deterministic_risk_score >= 90 or x.strong_signal_count >= 4:
            return PolicyDecision(
                FinalDisposition.HUMAN_REVIEW,
                "deterministic_critical_risk",
            )
        if x.deterministic_risk_score >= 70:
            return PolicyDecision(
                FinalDisposition.QUARANTINE,
                "deterministic_high_risk",
            )
        if x.deterministic_risk_score >= 40:
            return PolicyDecision(
                FinalDisposition.MONITOR,
                "deterministic_medium_risk",
            )
        return PolicyDecision(
            FinalDisposition.ALLOW,
            "deterministic_low_risk",
        )

    @staticmethod
    def _recommendation(value: str | None) -> FinalDisposition | None:
        if value is None:
            return None
        try:
            return FinalDisposition(value.strip().upper())
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _validate(x: PolicyInput) -> None:
        if not 0.0 <= x.deterministic_risk_score <= 100.0:
            raise ValueError("deterministic_risk_score must be between 0 and 100")
        if x.strong_signal_count < 0:
            raise ValueError("strong_signal_count must be >= 0")
        if x.agent_confidence is not None and not 0.0 <= x.agent_confidence <= 1.0:
            raise ValueError("agent_confidence must be between 0 and 1")
