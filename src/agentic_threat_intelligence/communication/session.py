from dataclasses import dataclass, field
from .envelope import AgentEnvelope
@dataclass
class ConversationState:
    correlation_id:str; messages:list[AgentEnvelope]=field(default_factory=list); invocation_count_by_agent:dict[str,int]=field(default_factory=dict); max_agent_invocations:int=20
    def append(self,m):
        if sum(self.invocation_count_by_agent.values())>=self.max_agent_invocations: raise RuntimeError('Conversation invocation budget exceeded')
        self.messages.append(m); self.invocation_count_by_agent[m.recipient]=self.invocation_count_by_agent.get(m.recipient,0)+1
