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


RISK_TRIAGE_OUTPUT_CONTRACT = "RiskTriageResult/v1"
_ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_ALLOWED_DISPOSITIONS = {"ALLOW", "MONITOR", "QUARANTINE", "HUMAN_REVIEW"}


class RiskTriageResponseError(ValueError):
    pass


@dataclass(frozen=True)
class RiskTriageTask:
    deterministic_evidence: DeterministicEvidence
    message_result: AgentResult
    threat_result: AgentResult | None


class RiskTriageAgent(SpecializedAgent):
    name = "risk-triage"
    version = "1.0"

    _system_instruction = """
You are the Risk / Triage specialist in a cybersecurity email-triage system.

Synthesize deterministic evidence and validated specialist findings.
Do not execute tools. Do not make the final security decision.
Your recommendation is advisory and will be evaluated by deterministic policy.
Do not downgrade or ignore explicit deterministic strong signals.
Do not invent evidence.

Return exactly one JSON object:
{
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "summary": "short evidence-based risk summary",
  "confidence": 0.0,
  "recommended_disposition": "ALLOW|MONITOR|QUARANTINE|HUMAN_REVIEW",
  "findings": [
    {"type": "risk_signal", "summary": "finding", "confidence": 0.0}
  ]
}
""".strip()

    def __init__(self, *, model: ReasoningModel, prompt_boundary_builder: PromptBoundaryBuilder | None = None) -> None:
        self._model = model
        self._boundary = prompt_boundary_builder or PromptBoundaryBuilder()

    async def handle(self, task: RiskTriageTask, context: AgentContext) -> AgentResult:
        if not isinstance(task, RiskTriageTask):
            raise TypeError("RiskTriageAgent requires RiskTriageTask")

        evidence = {
            "deterministic": {
                "risk_score": task.deterministic_evidence.risk_score,
                "strong_signal_count": task.deterministic_evidence.strong_signal_count,
                "ml_label": task.deterministic_evidence.ml_label,
                "ml_confidence": task.deterministic_evidence.ml_confidence,
                "security_signals": list(task.deterministic_evidence.security_signals),
            },
            "message_intelligence": self._result_view(task.message_result),
            "threat_intelligence": (
                self._result_view(task.threat_result)
                if task.threat_result is not None
                else None
            ),
        }
        boundary = self._boundary.build(
            system_instruction=self._system_instruction,
            evidence=(
                UntrustedEvidence(
                    source="triage-evidence",
                    origin=ContentOrigin.SECURITY_EVIDENCE,
                    content=json.dumps(evidence, ensure_ascii=False, sort_keys=True, default=str),
                ),
            ),
        )
        response = await self._model.complete(
            ModelRequest(
                system_instruction=boundary.system_instruction,
                user_content=boundary.user_content,
                response_schema_name=RISK_TRIAGE_OUTPUT_CONTRACT,
                trace_id=context.trace_id,
            )
        )
        payload = self._parse(response.text)
        findings = tuple(
            AgentFinding(
                finding_type=item["type"],
                summary=item["summary"],
                confidence=item["confidence"],
                attributes={"source": "risk-triage"},
            )
            for item in payload["findings"]
        )
        return AgentResult(
            task="risk.assess",
            output_contract=RISK_TRIAGE_OUTPUT_CONTRACT,
            findings=findings,
            recommendation=payload["recommended_disposition"],
            confidence=payload["confidence"],
            attributes={
                "severity": payload["severity"],
                "summary": payload["summary"],
                "prompt_injection_signals": boundary.injection_signals,
                "model_provider": response.provider,
                "model_name": response.model_name,
                "model_latency_ms": response.latency_ms,
            },
        )

    @staticmethod
    def _result_view(result: AgentResult) -> Mapping[str, Any]:
        return {
            "task": result.task,
            "confidence": result.confidence,
            "recommendation": result.recommendation,
            "findings": [
                {
                    "type": f.finding_type,
                    "summary": f.summary,
                    "confidence": f.confidence,
                    "attributes": dict(f.attributes),
                }
                for f in result.findings
            ],
            "attributes": dict(result.attributes),
        }

    @classmethod
    def _parse(cls, text: str) -> dict[str, Any]:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RiskTriageResponseError("model response is not valid JSON") from exc
        if not isinstance(raw, dict):
            raise RiskTriageResponseError("model response must be an object")
        severity = cls._required_string(raw, "severity").upper()
        if severity not in _ALLOWED_SEVERITIES:
            raise RiskTriageResponseError("unsupported severity")
        disposition = cls._required_string(raw, "recommended_disposition").upper()
        if disposition not in _ALLOWED_DISPOSITIONS:
            raise RiskTriageResponseError("unsupported recommended_disposition")
        confidence = cls._confidence(raw.get("confidence"), "confidence")
        summary = cls._required_string(raw, "summary")
        findings_raw = raw.get("findings", [])
        if not isinstance(findings_raw, list):
            raise RiskTriageResponseError("findings must be an array")
        findings=[]
        for i,item in enumerate(findings_raw):
            if not isinstance(item, dict):
                raise RiskTriageResponseError(f"findings[{i}] must be an object")
            findings.append({
                "type": cls._required_string(item, "type"),
                "summary": cls._required_string(item, "summary"),
                "confidence": cls._confidence(item.get("confidence"), f"findings[{i}].confidence"),
            })
        return {
            "severity": severity,
            "summary": summary,
            "confidence": confidence,
            "recommended_disposition": disposition,
            "findings": findings,
        }

    @staticmethod
    def _required_string(obj: Mapping[str, Any], key: str) -> str:
        value=obj.get(key)
        if not isinstance(value,str) or not value.strip():
            raise RiskTriageResponseError(f"{key} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _confidence(value: Any, field_name: str) -> float:
        if isinstance(value,bool) or not isinstance(value,(int,float)):
            raise RiskTriageResponseError(f"{field_name} must be numeric")
        result=float(value)
        if not 0.0 <= result <= 1.0:
            raise RiskTriageResponseError(f"{field_name} must be between 0 and 1")
        return result
