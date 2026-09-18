from agentic_threat_intelligence.security.identity import (
    PrincipalType,
    SecurityPrincipal,
)
from agentic_threat_intelligence.security.tool_authorization import (
    ToolAccessRule,
    ToolAuthorizationPolicy,
    ToolRisk,
)


def test_tool_authorization_allows_expected_agent_and_scope():
    principal = SecurityPrincipal(
        subject_id="agent:threat-intelligence",
        principal_type=PrincipalType.AGENT,
        scopes=frozenset({"threatintel.read"}),
    )
    policy = ToolAuthorizationPolicy(
        [
            ToolAccessRule(
                name="threat-intel-read",
                tool_pattern="virustotal.lookup_*",
                allowed_subject_patterns=frozenset(
                    {"agent:threat-intelligence"}
                ),
                required_scopes=frozenset({"threatintel.read"}),
                allowed_argument_keys=frozenset({"url"}),
            )
        ]
    )

    decision = policy.authorize(
        principal=principal,
        tool_name="virustotal.lookup_url",
        arguments={"url": "https://example.test"},
    )

    assert decision.allowed is True


def test_tool_authorization_denies_unapproved_agent():
    principal = SecurityPrincipal(
        subject_id="agent:message-intelligence",
        principal_type=PrincipalType.AGENT,
        scopes=frozenset({"threatintel.read"}),
    )
    policy = ToolAuthorizationPolicy(
        [
            ToolAccessRule(
                name="threat-intel-read",
                tool_pattern="virustotal.lookup_*",
                allowed_subject_patterns=frozenset(
                    {"agent:threat-intelligence"}
                ),
                required_scopes=frozenset({"threatintel.read"}),
            )
        ]
    )

    decision = policy.authorize(
        principal=principal,
        tool_name="virustotal.lookup_url",
        arguments={"url": "https://example.test"},
    )

    assert decision.allowed is False
    assert decision.reason == "principal_not_allowed"


def test_destructive_tool_requires_human_approval():
    principal = SecurityPrincipal(
        subject_id="agent:policy-response",
        principal_type=PrincipalType.AGENT,
        scopes=frozenset({"mail.quarantine"}),
    )
    policy = ToolAuthorizationPolicy(
        [
            ToolAccessRule(
                name="mail-delete",
                tool_pattern="mail.delete",
                allowed_subject_patterns=frozenset(
                    {"agent:policy-response"}
                ),
                required_scopes=frozenset({"mail.quarantine"}),
                risk=ToolRisk.DESTRUCTIVE,
                require_human_approval=True,
            )
        ]
    )

    denied = policy.authorize(
        principal=principal,
        tool_name="mail.delete",
        arguments={"message_id": "m-1"},
        human_approved=False,
    )
    allowed = policy.authorize(
        principal=principal,
        tool_name="mail.delete",
        arguments={"message_id": "m-1"},
        human_approved=True,
    )

    assert denied.allowed is False
    assert denied.reason == "human_approval_required"
    assert allowed.allowed is True
