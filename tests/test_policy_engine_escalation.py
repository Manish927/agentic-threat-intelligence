import pytest

from agentic_threat_intelligence.policy.engine import (
    DeterministicPolicyEngine,
    FinalDisposition,
    PolicyInput,
)


def test_agent_cannot_downgrade_deterministic_quarantine():
    decision=DeterministicPolicyEngine().evaluate(PolicyInput(75,1,"ALLOW",0.99))
    assert decision.disposition is FinalDisposition.QUARANTINE
    assert decision.agent_escalation_applied is False


def test_high_confidence_agent_quarantine_from_low_risk_requires_human():
    decision=DeterministicPolicyEngine().evaluate(PolicyInput(20,0,"QUARANTINE",0.95))
    assert decision.disposition is FinalDisposition.HUMAN_REVIEW
    assert decision.reason_code == "agent_quarantine_requires_human_review"
    assert decision.agent_escalation_applied is True


def test_monitor_recommendation_can_increase_scrutiny_without_destructive_action():
    decision=DeterministicPolicyEngine().evaluate(PolicyInput(20,0,"MONITOR",0.90))
    assert decision.disposition is FinalDisposition.MONITOR
    assert decision.agent_escalation_applied is True


def test_invalid_policy_input_is_rejected():
    with pytest.raises(ValueError):
        DeterministicPolicyEngine().evaluate(PolicyInput(101,0,None,None))
