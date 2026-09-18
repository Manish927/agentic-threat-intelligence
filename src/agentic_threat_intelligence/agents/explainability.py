from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from agentic_threat_intelligence.agents.base import AgentContext, SpecializedAgent
from agentic_threat_intelligence.communication.contracts import AgentResult
from agentic_threat_intelligence.models.reasoning import ModelRequest, ReasoningModel
from agentic_threat_intelligence.policy.engine import PolicyDecision
from agentic_threat_intelligence.security.prompt_boundary import (
    ContentOrigin,
    PromptBoundaryBuilder,
    UntrustedEvidence,
)


EXPLAINABILITY_OUTPUT_CONTRACT = "ExplainabilityResult/v1"


class ExplainabilityResponseError(ValueError):
    pass


@dataclass(frozen=True)
class ExplainabilityTask:
    policy_decision: PolicyDecision
    risk_result: AgentResult
    policy_result: AgentResult


class ExplainabilityAgent(SpecializedAgent):
    name = "explainability"
    version = "1.0"

    _system_instruction = """
You are the post-decision Explainability specialist.
The final disposition has already been made by deterministic policy.
Explain it; do not change, reinterpret, or recommend a different disposition.
Do not execute tools.

Return exactly one JSON object:
{
  "analyst_summary": "short explanation",
  "decision_rationale": "why deterministic policy produced this result",
  "key_evidence": ["evidence item"],
  "human_action": "action for analyst or null"
}
""".strip()

    def __init__(self, *, model: ReasoningModel, prompt_boundary_builder: PromptBoundaryBuilder | None = None) -> None:
        self._model=model
        self._boundary=prompt_boundary_builder or PromptBoundaryBuilder()

    async def handle(self, task: ExplainabilityTask, context: AgentContext) -> AgentResult:
        if not isinstance(task, ExplainabilityTask):
            raise TypeError("ExplainabilityAgent requires ExplainabilityTask")
        evidence={
            "final_disposition": task.policy_decision.disposition.value,
            "policy_reason": task.policy_decision.reason_code,
            "agent_escalation_applied": task.policy_decision.agent_escalation_applied,
            "risk_summary": task.risk_result.attributes.get("summary"),
            "risk_severity": task.risk_result.attributes.get("severity"),
            "policy_recommendation": task.policy_result.recommendation,
            "policy_reasons": task.policy_result.attributes.get("reasons", ()),
        }
        boundary=self._boundary.build(
            system_instruction=self._system_instruction,
            evidence=(UntrustedEvidence(
                source="final-decision-evidence",
                origin=ContentOrigin.SECURITY_EVIDENCE,
                content=json.dumps(evidence, ensure_ascii=False, sort_keys=True, default=str),
            ),),
        )
        response=await self._model.complete(ModelRequest(
            system_instruction=boundary.system_instruction,
            user_content=boundary.user_content,
            response_schema_name=EXPLAINABILITY_OUTPUT_CONTRACT,
            trace_id=context.trace_id,
        ))
        payload=self._parse(response.text)
        return AgentResult(
            task="decision.explain",
            output_contract=EXPLAINABILITY_OUTPUT_CONTRACT,
            findings=(),
            recommendation=None,
            confidence=None,
            attributes={
                **payload,
                "final_disposition": task.policy_decision.disposition.value,
                "policy_reason": task.policy_decision.reason_code,
                "model_provider": response.provider,
                "model_name": response.model_name,
                "model_latency_ms": response.latency_ms,
            },
        )

    @staticmethod
    def _parse(text:str)->dict[str,Any]:
        try: raw=json.loads(text)
        except json.JSONDecodeError as exc:
            raise ExplainabilityResponseError("model response is not valid JSON") from exc
        if not isinstance(raw,dict): raise ExplainabilityResponseError("model response must be an object")
        for key in ("analyst_summary","decision_rationale"):
            if not isinstance(raw.get(key),str) or not raw[key].strip():
                raise ExplainabilityResponseError(f"{key} must be a non-empty string")
        evidence=raw.get("key_evidence")
        if not isinstance(evidence,list) or not all(isinstance(x,str) and x.strip() for x in evidence):
            raise ExplainabilityResponseError("key_evidence must be a string array")
        human=raw.get("human_action")
        if human is not None and (not isinstance(human,str) or not human.strip()):
            raise ExplainabilityResponseError("human_action must be null or a non-empty string")
        return {
            "analyst_summary": raw["analyst_summary"].strip(),
            "decision_rationale": raw["decision_rationale"].strip(),
            "key_evidence": tuple(x.strip() for x in evidence),
            "human_action": human.strip() if isinstance(human,str) else None,
        }
