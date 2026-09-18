from __future__ import annotations

from typing import NotRequired, TypedDict

from langgraph.graph import END, START, StateGraph

from agentic_threat_intelligence.agents.base import AgentContext
from agentic_threat_intelligence.agents.explainability import (
    ExplainabilityAgent,
    ExplainabilityTask,
)
from agentic_threat_intelligence.agents.message_intelligence import MessageIntelligenceTask
from agentic_threat_intelligence.agents.policy_response import PolicyResponseAgent, PolicyResponseTask
from agentic_threat_intelligence.agents.risk_triage import RiskTriageAgent, RiskTriageTask
from agentic_threat_intelligence.agents.threat_intelligence import ThreatIntelligenceTask
from agentic_threat_intelligence.communication.contracts import AgentResult
from agentic_threat_intelligence.decision.models import DeterministicEvidence, FinalTriageDecision
from agentic_threat_intelligence.policy.engine import DeterministicPolicyEngine, PolicyDecision, PolicyInput
from agentic_threat_intelligence.workflows.triage import TriageWorkflow, TriageWorkflowResult


class DecisionWorkflowState(TypedDict):
    message_task: MessageIntelligenceTask
    threat_task: ThreatIntelligenceTask
    deterministic_evidence: DeterministicEvidence
    context: AgentContext
    specialist_analysis: NotRequired[TriageWorkflowResult]
    risk_result: NotRequired[AgentResult]
    policy_result: NotRequired[AgentResult]
    policy_decision: NotRequired[PolicyDecision]
    explainability_result: NotRequired[AgentResult]


class DecisionWorkflow:
    """Hierarchical LangGraph workflow for the full decision path."""

    def __init__(
        self,
        *,
        triage_workflow: TriageWorkflow,
        risk_triage_agent: RiskTriageAgent,
        policy_response_agent: PolicyResponseAgent,
        policy_engine: DeterministicPolicyEngine,
        explainability_agent: ExplainabilityAgent,
    ) -> None:
        self._triage_workflow=triage_workflow
        self._risk_triage_agent=risk_triage_agent
        self._policy_response_agent=policy_response_agent
        self._policy_engine=policy_engine
        self._explainability_agent=explainability_agent

        builder=StateGraph(DecisionWorkflowState)
        builder.add_node("specialist_analysis", self._specialist_analysis_node)
        builder.add_node("risk_triage", self._risk_triage_node)
        builder.add_node("policy_response", self._policy_response_node)
        builder.add_node("deterministic_policy", self._deterministic_policy_node)
        builder.add_node("explainability", self._explainability_node)
        builder.add_edge(START,"specialist_analysis")
        builder.add_edge("specialist_analysis","risk_triage")
        builder.add_edge("risk_triage","policy_response")
        builder.add_edge("policy_response","deterministic_policy")
        builder.add_edge("deterministic_policy","explainability")
        builder.add_edge("explainability",END)
        self._graph=builder.compile()

    async def _specialist_analysis_node(self,state:DecisionWorkflowState)->dict:
        result=await self._triage_workflow.run(
            message_task=state["message_task"],
            threat_task=state["threat_task"],
            context=state["context"],
        )
        return {"specialist_analysis":result}

    async def _risk_triage_node(self,state:DecisionWorkflowState)->dict:
        analysis=state["specialist_analysis"]
        result=await self._risk_triage_agent.handle(
            RiskTriageTask(
                deterministic_evidence=state["deterministic_evidence"],
                message_result=analysis.message_intelligence,
                threat_result=analysis.threat_intelligence,
            ),
            state["context"],
        )
        return {"risk_result":result}

    async def _policy_response_node(self,state:DecisionWorkflowState)->dict:
        result=await self._policy_response_agent.handle(
            PolicyResponseTask(
                deterministic_evidence=state["deterministic_evidence"],
                risk_result=state["risk_result"],
            ),
            state["context"],
        )
        return {"policy_result":result}

    async def _deterministic_policy_node(self,state:DecisionWorkflowState)->dict:
        evidence=state["deterministic_evidence"]
        recommendation=state["policy_result"]
        decision=self._policy_engine.evaluate(PolicyInput(
            deterministic_risk_score=evidence.risk_score,
            strong_signal_count=evidence.strong_signal_count,
            agent_recommendation=recommendation.recommendation,
            agent_confidence=recommendation.confidence,
        ))
        return {"policy_decision":decision}

    async def _explainability_node(self,state:DecisionWorkflowState)->dict:
        result=await self._explainability_agent.handle(
            ExplainabilityTask(
                policy_decision=state["policy_decision"],
                risk_result=state["risk_result"],
                policy_result=state["policy_result"],
            ),
            state["context"],
        )
        return {"explainability_result":result}

    async def run(
        self,
        *,
        message_task: MessageIntelligenceTask,
        threat_task: ThreatIntelligenceTask,
        deterministic_evidence: DeterministicEvidence,
        context: AgentContext,
    ) -> FinalTriageDecision:
        output=await self._graph.ainvoke({
            "message_task":message_task,
            "threat_task":threat_task,
            "deterministic_evidence":deterministic_evidence,
            "context":context,
        })
        analysis=output["specialist_analysis"]
        decision=output["policy_decision"]
        return FinalTriageDecision(
            final_disposition=decision.disposition,
            policy_reason=decision.reason_code,
            human_review_required=(decision.disposition.value == "HUMAN_REVIEW"),
            message_intelligence=analysis.message_intelligence,
            threat_intelligence=analysis.threat_intelligence,
            risk_triage=output["risk_result"],
            policy_response=output["policy_result"],
            explainability=output["explainability_result"],
        )
