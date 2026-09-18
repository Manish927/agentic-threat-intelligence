import json
import pytest

from agentic_threat_intelligence.agents.base import AgentContext
from agentic_threat_intelligence.agents.explainability import ExplainabilityAgent
from agentic_threat_intelligence.agents.message_intelligence import MessageIntelligenceAgent, MessageIntelligenceTask
from agentic_threat_intelligence.agents.orchestrator import TriageOrchestrator
from agentic_threat_intelligence.agents.policy_response import PolicyResponseAgent
from agentic_threat_intelligence.agents.risk_triage import RiskTriageAgent
from agentic_threat_intelligence.agents.threat_intelligence import ThreatIntelligenceAgent, ThreatIntelligenceTask
from agentic_threat_intelligence.decision.models import DeterministicEvidence
from agentic_threat_intelligence.mcp.adapter import MCPToolAdapter
from agentic_threat_intelligence.mcp.secure_adapter import SecuredMCPToolAdapter
from agentic_threat_intelligence.models.reasoning import ModelResponse
from agentic_threat_intelligence.policy.engine import DeterministicPolicyEngine, FinalDisposition
from agentic_threat_intelligence.security.default_policies import THREAT_INTEL_AGENT_SUBJECT, THREAT_INTEL_READ_SCOPE, build_threat_intelligence_tool_policy
from agentic_threat_intelligence.security.identity import PrincipalType, SecurityPrincipal
from agentic_threat_intelligence.workflows.decision import DecisionWorkflow
from agentic_threat_intelligence.workflows.triage import TriageWorkflow


class DecisionModel:
    async def complete(self, request):
        responses={
            "MessageIntelligenceResult/v1": {"intent":"Credential theft","summary":"Urgent credential verification.","confidence":0.96,"signals":[{"type":"urgency","summary":"Immediate suspension is threatened.","confidence":0.97}],"recommended_follow_up":["indicator.enrich"]},
            "RiskTriageResult/v1": {"severity":"CRITICAL","summary":"Independent evidence sources agree.","confidence":0.98,"recommended_disposition":"HUMAN_REVIEW","findings":[{"type":"combined_risk","summary":"Message and reputation evidence align.","confidence":0.98}]},
            "PolicyResponseResult/v1": {"recommended_disposition":"QUARANTINE","confidence":0.97,"requires_human_review":True,"reasons":["Credential theft evidence is high confidence."]},
            "ExplainabilityResult/v1": {"analyst_summary":"Critical phishing case requires analyst review.","decision_rationale":"Deterministic risk score and strong signals crossed the human-review boundary.","key_evidence":["Risk score 97.5","Malicious URL reputation"],"human_action":"Review the evidence before containment."},
        }
        return ModelResponse(json.dumps(responses[request.response_schema_name]),"decision-test-model","test",1.0)


class IntelClient:
    async def call_tool(self, tool_name, arguments):
        return {"verdict":"malicious","confidence":0.98,"provider":"test-intel"}


def build_orchestrator():
    model=DecisionModel()
    message=MessageIntelligenceAgent(model=model)
    threat=ThreatIntelligenceAgent(
        mcp=SecuredMCPToolAdapter(
            transport=MCPToolAdapter(client=IntelClient()),
            authorizer=build_threat_intelligence_tool_policy(),
        ),
        principal=SecurityPrincipal(
            subject_id=THREAT_INTEL_AGENT_SUBJECT,
            principal_type=PrincipalType.AGENT,
            scopes=frozenset({THREAT_INTEL_READ_SCOPE}),
        ),
    )
    triage=TriageWorkflow(message_intelligence_agent=message,threat_intelligence_agent=threat)
    decision=DecisionWorkflow(
        triage_workflow=triage,
        risk_triage_agent=RiskTriageAgent(model=model),
        policy_response_agent=PolicyResponseAgent(model=model),
        policy_engine=DeterministicPolicyEngine(),
        explainability_agent=ExplainabilityAgent(model=model),
    )
    return TriageOrchestrator(decision_workflow=decision)


@pytest.mark.asyncio
async def test_end_to_end_decision_pipeline_keeps_deterministic_authority():
    result=await build_orchestrator().decide_case(
        message_task=MessageIntelligenceTask(
            subject="URGENT account suspension",
            sanitized_body="Verify credentials immediately.",
            sender="security@example.invalid",
        ),
        threat_task=ThreatIntelligenceTask(urls=("https://evil.example/login",)),
        deterministic_evidence=DeterministicEvidence(
            risk_score=97.5,
            strong_signal_count=4,
            ml_label="THREAT",
            ml_confidence=0.9586,
            security_signals=("lang_urgency","url_suspicious_tld"),
        ),
        context=AgentContext("case-full-1","trace-full-1",None,{}),
    )
    assert result.policy_response.recommendation == "QUARANTINE"
    assert result.final_disposition is FinalDisposition.HUMAN_REVIEW
    assert result.policy_reason == "deterministic_critical_risk"
    assert result.human_review_required is True
    assert result.explainability.recommendation is None


@pytest.mark.asyncio
async def test_decision_orchestrator_requires_workflow():
    with pytest.raises(RuntimeError,match="Decision workflow is not configured"):
        await TriageOrchestrator().decide_case(
            message_task=MessageIntelligenceTask("x","y","z"),
            threat_task=ThreatIntelligenceTask(),
            deterministic_evidence=DeterministicEvidence(10,0),
            context=AgentContext("c","t",None,{}),
        )
