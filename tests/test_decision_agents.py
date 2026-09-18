import json
import pytest

from agentic_threat_intelligence.agents.base import AgentContext
from agentic_threat_intelligence.agents.explainability import ExplainabilityAgent, ExplainabilityTask
from agentic_threat_intelligence.agents.policy_response import PolicyResponseAgent, PolicyResponseTask
from agentic_threat_intelligence.agents.risk_triage import RiskTriageAgent, RiskTriageTask
from agentic_threat_intelligence.communication.contracts import AgentResult
from agentic_threat_intelligence.decision.models import DeterministicEvidence
from agentic_threat_intelligence.models.reasoning import ModelResponse
from agentic_threat_intelligence.policy.engine import FinalDisposition, PolicyDecision


class RoutingModel:
    async def complete(self, request):
        if request.response_schema_name == "RiskTriageResult/v1":
            payload={
                "severity":"CRITICAL",
                "summary":"Multiple independent signals indicate credential theft.",
                "confidence":0.98,
                "recommended_disposition":"HUMAN_REVIEW",
                "findings":[{"type":"combined_risk","summary":"Deterministic and threat-intel evidence agree.","confidence":0.98}],
            }
        elif request.response_schema_name == "PolicyResponseResult/v1":
            payload={
                "recommended_disposition":"QUARANTINE",
                "confidence":0.97,
                "requires_human_review":True,
                "reasons":["Credential theft evidence is high confidence."],
            }
        else:
            payload={
                "analyst_summary":"The case requires analyst review.",
                "decision_rationale":"Deterministic critical-risk policy required human review.",
                "key_evidence":["Critical deterministic risk"],
                "human_action":"Review and approve any containment action.",
            }
        return ModelResponse(json.dumps(payload),"test-model","test",1.0)


def context():
    return AgentContext("case-d1","trace-d1",None,{})


def specialist_result(task):
    return AgentResult(task,"Test/v1",(),None,0.9,{"summary":"typed specialist result"})


@pytest.mark.asyncio
async def test_risk_policy_and_explainability_agents_are_advisory():
    model=RoutingModel()
    evidence=DeterministicEvidence(97.5,4,"THREAT",0.96,("url_suspicious_tld","lang_urgency"))
    risk=await RiskTriageAgent(model=model).handle(
        RiskTriageTask(evidence,specialist_result("message.analyze"),specialist_result("indicator.enrich")),
        context(),
    )
    assert risk.recommendation == "HUMAN_REVIEW"
    policy=await PolicyResponseAgent(model=model).handle(PolicyResponseTask(evidence,risk),context())
    assert policy.recommendation == "QUARANTINE"
    explanation=await ExplainabilityAgent(model=model).handle(
        ExplainabilityTask(PolicyDecision(FinalDisposition.HUMAN_REVIEW,"deterministic_critical_risk"),risk,policy),
        context(),
    )
    assert explanation.recommendation is None
    assert explanation.attributes["final_disposition"] == "HUMAN_REVIEW"
