from dataclasses import dataclass, field
@dataclass(frozen=True)
class AgentCapability:
    agent_name:str; version:str; description:str
    supported_tasks:frozenset[str]; accepted_contracts:frozenset[str]; produced_contracts:frozenset[str]
    required_scopes:frozenset[str]=field(default_factory=frozenset); priority:int=100; endpoint:str|None=None
