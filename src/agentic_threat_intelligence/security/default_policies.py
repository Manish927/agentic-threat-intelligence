from __future__ import annotations

from agentic_threat_intelligence.security.tool_authorization import (
    ToolAccessRule,
    ToolAuthorizationPolicy,
    ToolRisk,
)


THREAT_INTEL_READ_SCOPE = "threat-intel:read"
THREAT_INTEL_AGENT_SUBJECT = "agent:threat-intelligence"


def build_threat_intelligence_tool_policy() -> ToolAuthorizationPolicy:
    """Default deny-by-default policy for read-only threat intel tools."""

    return ToolAuthorizationPolicy(
        (
            ToolAccessRule(
                name="threat-intel-url-read",
                tool_pattern="threat_intel.url.lookup",
                allowed_subject_patterns=frozenset(
                    {THREAT_INTEL_AGENT_SUBJECT}
                ),
                required_scopes=frozenset(
                    {THREAT_INTEL_READ_SCOPE}
                ),
                allowed_argument_keys=frozenset({"url"}),
                risk=ToolRisk.READ_ONLY,
            ),
            ToolAccessRule(
                name="threat-intel-domain-read",
                tool_pattern="threat_intel.domain.lookup",
                allowed_subject_patterns=frozenset(
                    {THREAT_INTEL_AGENT_SUBJECT}
                ),
                required_scopes=frozenset(
                    {THREAT_INTEL_READ_SCOPE}
                ),
                allowed_argument_keys=frozenset({"domain"}),
                risk=ToolRisk.READ_ONLY,
            ),
            ToolAccessRule(
                name="threat-intel-ip-read",
                tool_pattern="threat_intel.ip.lookup",
                allowed_subject_patterns=frozenset(
                    {THREAT_INTEL_AGENT_SUBJECT}
                ),
                required_scopes=frozenset(
                    {THREAT_INTEL_READ_SCOPE}
                ),
                allowed_argument_keys=frozenset({"ip_address"}),
                risk=ToolRisk.READ_ONLY,
            ),
            ToolAccessRule(
                name="threat-intel-hash-read",
                tool_pattern="threat_intel.hash.lookup",
                allowed_subject_patterns=frozenset(
                    {THREAT_INTEL_AGENT_SUBJECT}
                ),
                required_scopes=frozenset(
                    {THREAT_INTEL_READ_SCOPE}
                ),
                allowed_argument_keys=frozenset({"file_hash"}),
                risk=ToolRisk.READ_ONLY,
            ),
        )
    )
