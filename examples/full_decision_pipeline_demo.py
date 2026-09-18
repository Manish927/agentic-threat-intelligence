from __future__ import annotations

import asyncio
import json

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
from agentic_threat_intelligence.policy.engine import DeterministicPolicyEngine
from agentic_threat_intelligence.security.audit import InMemorySecurityAuditSink
from agentic_threat_intelligence.security.default_policies import THREAT_INTEL_AGENT_SUBJECT, THREAT_INTEL_READ_SCOPE, build_threat_intelligence_tool_policy
from agentic_threat_intelligence.security.identity import PrincipalType, SecurityPrincipal
from agentic_threat_intelligence.workflows.decision import DecisionWorkflow
from agentic_threat_intelligence.workflows.triage import TriageWorkflow


class DemoModel:
    async def complete(self, request):
        responses={
            "MessageIntelligenceResult/v1": {"intent":"Credential theft","summary":"Security impersonation with urgent credential verification.","confidence":0.96,"signals":[{"type":"urgency","summary":"Immediate suspension is threatened.","confidence":0.97},{"type":"impersonation","summary":"The sender claims to represent Microsoft security.","confidence":0.94}],"recommended_follow_up":["indicator.enrich"]},
            "RiskTriageResult/v1": {"severity":"CRITICAL","summary":"ML, deterministic security, semantic analysis and reputation evidence agree.","confidence":0.99,"recommended_disposition":"HUMAN_REVIEW","findings":[{"type":"evidence_convergence","summary":"Independent evidence sources converge on credential theft.","confidence":0.99}]},
            "PolicyResponseResult/v1": {"recommended_disposition":"QUARANTINE","confidence":0.98,"requires_human_review":True,"reasons":["Credential-theft indicators are high confidence."]},
            "ExplainabilityResult/v1": {"analyst_summary":"High-confidence phishing evidence requires analyst review.","decision_rationale":"The deterministic critical-risk boundary overrides the advisory quarantine recommendation and requires human review.","key_evidence":["97.5 deterministic risk score","4 strong security signals","malicious URL/domain reputation","credential-theft intent"],"human_action":"Review evidence and approve or reject containment."},
        }
        return ModelResponse(json.dumps(responses[request.response_schema_name]),"offline-decision-demo","demo",0.0)


class DemoIntelClient:
    async def call_tool(self, tool_name, arguments):
        return {"verdict":"malicious","confidence":0.98,"provider":"offline-threat-intel-demo"}


async def main():
    model=DemoModel()
    audit=InMemorySecurityAuditSink()
    message=MessageIntelligenceAgent(model=model)
    threat=ThreatIntelligenceAgent(
        mcp=SecuredMCPToolAdapter(
            transport=MCPToolAdapter(client=DemoIntelClient()),
            authorizer=build_threat_intelligence_tool_policy(),
            audit_sink=audit,
        ),
        principal=SecurityPrincipal(
            subject_id=THREAT_INTEL_AGENT_SUBJECT,
            principal_type=PrincipalType.AGENT,
            scopes=frozenset({THREAT_INTEL_READ_SCOPE}),
        ),
    )
    triage=TriageWorkflow(message_intelligence_agent=message,threat_intelligence_agent=threat)
    workflow=DecisionWorkflow(
        triage_workflow=triage,
        risk_triage_agent=RiskTriageAgent(model=model),
        policy_response_agent=PolicyResponseAgent(model=model),
        policy_engine=DeterministicPolicyEngine(),
        explainability_agent=ExplainabilityAgent(model=model),
    )
    result=await TriageOrchestrator(decision_workflow=workflow).decide_case(
        message_task=MessageIntelligenceTask(
            subject="URGENT: Your Microsoft 365 account will be suspended",
            sanitized_body="We detected unusual sign-in activity. Verify your identity within two hours.",
            sender="Microsoft Security <security-alert@microsoft-account-verify.com>",
            language_features={"urgency":True,"suspension":True},
        ),
        threat_task=ThreatIntelligenceTask(
            urls=("https://microsoft-account-verify.xyz/account/verify-credentials",),
            domains=("microsoft-account-verify.xyz",),
        ),
        deterministic_evidence=DeterministicEvidence(
            risk_score=97.5,
            strong_signal_count=4,
            ml_label="THREAT",
            ml_confidence=0.9586,
            security_signals=("lang_urgency","lang_suspension","url_suspicious_tld","url_credential_path"),
        ),
        context=AgentContext("demo-final-case","demo-final-trace",None,{}),
    )
    print("Message intent:", result.message_intelligence.attributes["intent"])
    print("Risk severity:", result.risk_triage.attributes["severity"])
    print("Policy agent recommendation:", result.policy_response.recommendation)
    print("FINAL deterministic disposition:", result.final_disposition.value)
    print("Policy reason:", result.policy_reason)
    print("Human review required:", result.human_review_required)
    print("Explanation:", result.explainability.attributes["analyst_summary"])
    print("Security audit events:", len(audit.events))


if __name__ == "__main__":
    asyncio.run(main())
