import pytest

from agentic_threat_intelligence.communication.capability import (
    AgentCapability,
)
from agentic_threat_intelligence.communication.registry import (
    CapabilityNotFound,
    CapabilityRegistry,
)


def test_registry_resolves_only_capability_allowed_by_scopes():
    registry = CapabilityRegistry()
    registry.register(
        AgentCapability(
            agent_name="threat-intelligence",
            version="1",
            description="threat intelligence",
            supported_tasks=frozenset({"indicator.enrich"}),
            accepted_contracts=frozenset({"Req/v1"}),
            produced_contracts=frozenset({"Res/v1"}),
            required_scopes=frozenset({"threatintel.read"}),
        )
    )

    selected = registry.resolve_for_scopes(
        "indicator.enrich",
        {"threatintel.read"},
    )
    assert selected.agent_name == "threat-intelligence"

    with pytest.raises(CapabilityNotFound):
        registry.resolve_for_scopes(
            "indicator.enrich",
            {"message.read"},
        )
