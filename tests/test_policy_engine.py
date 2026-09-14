from agentic_threat_intelligence.policy.engine import DeterministicPolicyEngine, FinalDisposition, PolicyInput

def test_critical_case_requires_human_review():
    r=DeterministicPolicyEngine().decide(PolicyInput(97.5,4,'QUARANTINE',0.99))
    assert r == FinalDisposition.HUMAN_REVIEW
