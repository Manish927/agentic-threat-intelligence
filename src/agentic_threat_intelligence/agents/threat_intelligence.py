from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Mapping

from agentic_threat_intelligence.agents.base import (
    AgentContext,
    SpecializedAgent,
)
from agentic_threat_intelligence.communication.contracts import (
    AgentFinding,
    AgentResult,
)
from agentic_threat_intelligence.mcp.secure_adapter import (
    SecuredMCPToolAdapter,
    ToolAuthorizationError,
)
from agentic_threat_intelligence.security.identity import (
    PrincipalType,
    SecurityPrincipal,
)


THREAT_INTELLIGENCE_OUTPUT_CONTRACT = "ThreatIntelligenceResult/v1"


class ThreatIntelligenceResponseError(ValueError):
    """Raised when an MCP threat-intelligence result violates its contract."""


@dataclass(frozen=True)
class ThreatIntelligenceTask:
    urls: tuple[str, ...] = field(default_factory=tuple)
    domains: tuple[str, ...] = field(default_factory=tuple)
    ip_addresses: tuple[str, ...] = field(default_factory=tuple)
    file_hashes: tuple[str, ...] = field(default_factory=tuple)

    def has_indicators(self) -> bool:
        return any(
            (
                self.urls,
                self.domains,
                self.ip_addresses,
                self.file_hashes,
            )
        )

    def unique_indicators(
        self,
    ) -> tuple[tuple[str, str, str, str], ...]:
        """Return `(kind, value, tool_name, argument_name)` tuples."""

        items: list[tuple[str, str, str, str]] = []
        specs = (
            ("url", self.urls, "threat_intel.url.lookup", "url"),
            (
                "domain",
                self.domains,
                "threat_intel.domain.lookup",
                "domain",
            ),
            (
                "ip_address",
                self.ip_addresses,
                "threat_intel.ip.lookup",
                "ip_address",
            ),
            (
                "file_hash",
                self.file_hashes,
                "threat_intel.hash.lookup",
                "file_hash",
            ),
        )

        for kind, values, tool_name, argument_name in specs:
            seen: set[str] = set()
            for value in values:
                normalized = value.strip()
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                items.append(
                    (kind, normalized, tool_name, argument_name)
                )

        return tuple(items)


@dataclass(frozen=True)
class _LookupOutcome:
    finding: AgentFinding | None = None
    provider: str | None = None
    error: str | None = None


class ThreatIntelligenceAgent(SpecializedAgent):
    """Read-only threat-intelligence enrichment specialist.

    The agent can only reach external providers through `SecuredMCPToolAdapter`.
    Tool authorization therefore remains deterministic and outside the agent's
    reasoning path.
    """

    name = "threat-intelligence"
    version = "1.0"

    def __init__(
        self,
        *,
        mcp: SecuredMCPToolAdapter,
        principal: SecurityPrincipal,
        max_concurrency: int = 8,
    ) -> None:
        if principal.principal_type is not PrincipalType.AGENT:
            raise ValueError(
                "ThreatIntelligenceAgent requires an AGENT principal"
            )
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")

        self._mcp = mcp
        self._principal = principal
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def handle(
        self,
        task: ThreatIntelligenceTask,
        context: AgentContext,
    ) -> AgentResult:
        if not isinstance(task, ThreatIntelligenceTask):
            raise TypeError(
                "ThreatIntelligenceAgent requires ThreatIntelligenceTask"
            )

        indicators = task.unique_indicators()
        if not indicators:
            return AgentResult(
                task="indicator.enrich",
                output_contract=THREAT_INTELLIGENCE_OUTPUT_CONTRACT,
                findings=(),
                recommendation=None,
                confidence=None,
                attributes={
                    "lookup_count": 0,
                    "providers": (),
                    "errors": (),
                    "skipped": True,
                },
            )

        outcomes = await asyncio.gather(
            *(
                self._lookup(
                    kind=kind,
                    value=value,
                    tool_name=tool_name,
                    argument_name=argument_name,
                    context=context,
                )
                for kind, value, tool_name, argument_name in indicators
            )
        )

        findings = tuple(
            outcome.finding
            for outcome in outcomes
            if outcome.finding is not None
        )
        providers = tuple(
            sorted(
                {
                    outcome.provider
                    for outcome in outcomes
                    if outcome.provider
                }
            )
        )
        errors = tuple(
            outcome.error
            for outcome in outcomes
            if outcome.error is not None
        )

        confidence = (
            max(finding.confidence for finding in findings)
            if findings
            else None
        )

        return AgentResult(
            task="indicator.enrich",
            output_contract=THREAT_INTELLIGENCE_OUTPUT_CONTRACT,
            findings=findings,
            recommendation=None,
            confidence=confidence,
            attributes={
                "lookup_count": len(indicators),
                "providers": providers,
                "errors": errors,
                "skipped": False,
            },
        )

    async def _lookup(
        self,
        *,
        kind: str,
        value: str,
        tool_name: str,
        argument_name: str,
        context: AgentContext,
    ) -> _LookupOutcome:
        try:
            async with self._semaphore:
                raw = await self._mcp.invoke(
                    principal=self._principal,
                    case_id=context.case_id,
                    trace_id=context.trace_id,
                    tool_name=tool_name,
                    arguments={argument_name: value},
                )
        except ToolAuthorizationError:
            # Authorization failures are security failures. Do not downgrade
            # them into a soft provider error.
            raise
        except Exception as exc:
            return _LookupOutcome(
                error=(
                    f"{kind}:{value}:"
                    f"tool_execution_failed:{type(exc).__name__}"
                )
            )

        try:
            finding, provider = self._validated_finding(
                kind=kind,
                value=value,
                raw=raw,
            )
        except ThreatIntelligenceResponseError as exc:
            return _LookupOutcome(
                error=f"{kind}:{value}:invalid_tool_result:{exc}"
            )

        return _LookupOutcome(
            finding=finding,
            provider=provider,
        )

    @classmethod
    def _validated_finding(
        cls,
        *,
        kind: str,
        value: str,
        raw: Mapping[str, Any],
    ) -> tuple[AgentFinding, str]:
        if not isinstance(raw, Mapping):
            raise ThreatIntelligenceResponseError(
                "tool result must be an object"
            )

        verdict_raw = raw.get("verdict")
        if not isinstance(verdict_raw, str):
            raise ThreatIntelligenceResponseError(
                "verdict must be a string"
            )

        verdict = verdict_raw.strip().lower()
        allowed_verdicts = {
            "malicious",
            "suspicious",
            "benign",
            "unknown",
        }
        if verdict not in allowed_verdicts:
            raise ThreatIntelligenceResponseError(
                f"unsupported verdict: {verdict}"
            )

        confidence_raw = raw.get("confidence")
        if (
            isinstance(confidence_raw, bool)
            or not isinstance(confidence_raw, (int, float))
        ):
            raise ThreatIntelligenceResponseError(
                "confidence must be numeric"
            )

        confidence = float(confidence_raw)
        if confidence < 0.0 or confidence > 1.0:
            raise ThreatIntelligenceResponseError(
                "confidence must be between 0.0 and 1.0"
            )

        provider_raw = raw.get("provider")
        if not isinstance(provider_raw, str) or not provider_raw.strip():
            raise ThreatIntelligenceResponseError(
                "provider must be a non-empty string"
            )
        provider = provider_raw.strip()

        # The summary is constructed locally instead of trusting arbitrary
        # provider text. Raw tool output remains external/untrusted data.
        summary = (
            f"{provider} classified {kind} '{value}' "
            f"as {verdict}."
        )

        return (
            AgentFinding(
                finding_type=f"threat_intel_{verdict}",
                summary=summary,
                confidence=confidence,
                attributes={
                    "indicator_type": kind,
                    "indicator_value": value,
                    "verdict": verdict,
                    "provider": provider,
                },
            ),
            provider,
        )
