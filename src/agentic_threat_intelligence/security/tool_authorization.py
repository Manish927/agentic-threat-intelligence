from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatch
from typing import Any, Mapping, Sequence

from .identity import SecurityPrincipal


class ToolRisk(StrEnum):
    READ_ONLY = "READ_ONLY"
    MUTATING = "MUTATING"
    DESTRUCTIVE = "DESTRUCTIVE"


@dataclass(frozen=True)
class ToolAccessRule:
    """One deterministic authorization rule for a tool/capability."""

    name: str
    tool_pattern: str
    allowed_subject_patterns: frozenset[str]
    required_scopes: frozenset[str] = frozenset()
    allowed_argument_keys: frozenset[str] | None = None
    risk: ToolRisk = ToolRisk.READ_ONLY
    require_human_approval: bool = False

    def matches_tool(self, tool_name: str) -> bool:
        return fnmatch(tool_name, self.tool_pattern)

    def allows_subject(self, subject_id: str) -> bool:
        return any(
            fnmatch(subject_id, pattern)
            for pattern in self.allowed_subject_patterns
        )


@dataclass(frozen=True)
class ToolAccessDecision:
    allowed: bool
    reason: str
    rule_name: str | None = None


class ToolAuthorizationPolicy:
    """Deny-by-default deterministic tool authorization."""

    def __init__(self, rules: Sequence[ToolAccessRule]) -> None:
        self._rules = tuple(rules)

    def authorize(
        self,
        *,
        principal: SecurityPrincipal,
        tool_name: str,
        arguments: Mapping[str, Any],
        human_approved: bool = False,
    ) -> ToolAccessDecision:
        if not principal.authenticated:
            return ToolAccessDecision(False, "principal_not_authenticated")

        matching = [r for r in self._rules if r.matches_tool(tool_name)]
        if not matching:
            return ToolAccessDecision(False, "no_matching_tool_rule")

        for rule in matching:
            if not rule.allows_subject(principal.subject_id):
                continue

            if not principal.has_scopes(rule.required_scopes):
                missing = sorted(rule.required_scopes - principal.scopes)
                return ToolAccessDecision(
                    False,
                    f"missing_required_scopes:{','.join(missing)}",
                    rule.name,
                )

            if rule.allowed_argument_keys is not None:
                unexpected = sorted(
                    set(arguments.keys()) - set(rule.allowed_argument_keys)
                )
                if unexpected:
                    return ToolAccessDecision(
                        False,
                        f"unexpected_tool_arguments:{','.join(unexpected)}",
                        rule.name,
                    )

            if rule.require_human_approval and not human_approved:
                return ToolAccessDecision(
                    False,
                    "human_approval_required",
                    rule.name,
                )

            return ToolAccessDecision(True, "authorized", rule.name)

        return ToolAccessDecision(False, "principal_not_allowed")
