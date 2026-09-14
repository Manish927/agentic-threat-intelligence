from agentic_threat_intelligence.communication.capability import AgentCapability
from agentic_threat_intelligence.communication.registry import CapabilityRegistry

def test_resolve_priority():
    r=CapabilityRegistry()
    r.register(AgentCapability('b','1','secondary',frozenset({'indicator.enrich'}),frozenset({'Req/v1'}),frozenset({'Res/v1'}),priority=50))
    r.register(AgentCapability('a','2','preferred',frozenset({'indicator.enrich'}),frozenset({'Req/v1'}),frozenset({'Res/v1'}),priority=10))
    assert r.resolve('indicator.enrich').agent_name=='a'
