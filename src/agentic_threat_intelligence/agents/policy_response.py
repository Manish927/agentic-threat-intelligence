from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from agentic_threat_intelligence.agents.base import AgentContext, SpecializedAgent
from agentic_threat_intelligence.communication.contracts import AgentFinding, AgentResult
from agentic_threat_intelligence.decision.models import DeterministicEvidence
from agentic_threat_intelligence.models.reasoning import ModelRequest, ReasoningModel
from agentic_threat_intelligence.security.prompt_boundary import (
    ContentOrigin,
    PromptBoundaryBuilder,
    UntrustedEvidence,
)


POLICY_RESPONSE_OUTPUT_CONTRACT = "PolicyResponseResult/v1"
_ALLOWED_DISPOSITIONS = {"ALLOW", "MONITOR", "QUARANTINE", "HUMAN_REVIEW"}


class PolicyResponseError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyResponseTask:
    deterministic_evidence: DeterministicEvidence
    risk_result: AgentResult


class PolicyResponseAgent(SpecializedAgent):
    name = "policy-response"
    version = "1.0"

    _system_instruction = """
You are the Policy / Response recommendation specialist.
Recommend exactly one approved disposition: ALLOW, MONITOR, QUARANTINE, or HUMAN_REVIEW.
Your recommendation is advisory only. You cannot execute actions and cannot override deterministic policy.
A recommendation to QUARANTINE does not authorize quarantine.
Do not invent evidence.

Return exactly one JSON object:
{
  "recommended_disposition": "ALLOW|MONITOR|QUARANTINE|HUMAN_REVIEW",
  "confidence": 0.0,
  "requires_human_review": true,
  "reasons": ["short reason"]
}
""".strip()

    def __init__(self, *, model: ReasoningModel, prompt_boundary_builder: PromptBoundaryBuilder | None = None) -> None:
        self._model=model
        self._boundary=prompt_boundary_builder or PromptBoundaryBuilder()

    async def handle(self, task: PolicyResponseTask, context: AgentContext) -> AgentResult:
        if not isinstance(task, PolicyResponseTask):
            raise TypeError("PolicyResponseAgent requires PolicyResponseTask")
        evidence={
            "deterministic_risk_score": task.deterministic_evidence.risk_score,
            "strong_signal_count": task.deterministic_evidence.strong_signal_count,
            "risk_recommendation": task.risk_result.recommendation,
            "risk_confidence": task.risk_result.confidence,
            "risk_severity": task.risk_result.attributes.get("severity"),
            "risk_summary": task.risk_result.attributes.get("summary"),
        }
        boundary=self._boundary.build(
            system_instruction=self._system_instruction,
            evidence=(UntrustedEvidence(
                source="risk-assessment",
                origin=ContentOrigin.SECURITY_EVIDENCE,
                content=json.dumps(evidence, ensure_ascii=False, sort_keys=True, default=str),
            ),),
        )
        response=await self._model.complete(ModelRequest(
            system_instruction=boundary.system_instruction,
            user_content=boundary.user_content,
            response_schema_name=POLICY_RESPONSE_OUTPUT_CONTRACT,
            trace_id=context.trace_id,
        ))
        payload=self._parse(response.text)
        findings=tuple(
            AgentFinding(
                finding_type="policy_reason",
                summary=reason,
                confidence=payload["confidence"],
                attributes={"source":"policy-response"},
            ) for reason in payload["reasons"]
        )
        return AgentResult(
            task="policy.recommend",
            output_contract=POLICY_RESPONSE_OUTPUT_CONTRACT,
            findings=findings,
            recommendation=payload["recommended_disposition"],
            confidence=payload["confidence"],
            attributes={
                "requires_human_review": payload["requires_human_review"],
                "reasons": tuple(payload["reasons"]),
                "model_provider": response.provider,
                "model_name": response.model_name,
                "model_latency_ms": response.latency_ms,
            },
        )

    @classmethod
    def _parse(cls,text:str)->dict[str,Any]:
        try: raw=json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyResponseError("model response is not valid JSON") from exc
        if not isinstance(raw,dict): raise PolicyResponseError("model response must be an object")
        disposition=raw.get("recommended_disposition")
        if not isinstance(disposition,str) or disposition.strip().upper() not in _ALLOWED_DISPOSITIONS:
            raise PolicyResponseError("unsupported recommended_disposition")
        confidence=raw.get("confidence")
        if isinstance(confidence,bool) or not isinstance(confidence,(int,float)) or not 0.0 <= float(confidence) <= 1.0:
            raise PolicyResponseError("confidence must be between 0 and 1")
        human=raw.get("requires_human_review")
        if not isinstance(human,bool): raise PolicyResponseError("requires_human_review must be boolean")
        reasons=raw.get("reasons")
        if not isinstance(reasons,list) or not reasons or not all(isinstance(r,str) and r.strip() for r in reasons):
            raise PolicyResponseError("reasons must be a non-empty string array")
        return {
            "recommended_disposition": disposition.strip().upper(),
            "confidence": float(confidence),
            "requires_human_review": human,
            "reasons": [r.strip() for r in reasons],
        }
