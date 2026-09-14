import asyncio
from collections import defaultdict
from typing import Awaitable, Callable, Protocol
from .envelope import AgentEnvelope
from .security import DisclosurePolicy
MessageHandler=Callable[[AgentEnvelope],Awaitable[AgentEnvelope|None]]
EventHandler=Callable[[AgentEnvelope],Awaitable[None]]
class AgentBus(Protocol):
    async def request(self,envelope:AgentEnvelope)->AgentEnvelope: ...
    async def publish(self,envelope:AgentEnvelope)->None: ...
class InMemoryAgentBus:
    def __init__(self, disclosure_policy:DisclosurePolicy): self._handlers={}; self._subscribers=defaultdict(list); self._policy=disclosure_policy
    def register_handler(self,name,handler): self._handlers[name]=handler
    def subscribe(self,topic,handler): self._subscribers[topic].append(handler)
    async def request(self,e):
        if e.hop_count>e.max_hops: raise RuntimeError('Agent message hop limit exceeded')
        h=self._handlers.get(e.recipient)
        if h is None: raise LookupError(f'No handler registered for {e.recipient}')
        safe=self._policy.filter_payload(recipient=e.recipient,payload=e.payload)
        delivered=AgentEnvelope(**{**e.__dict__,'payload':safe})
        result=await h(delivered)
        if result is None: raise RuntimeError(f'Handler {e.recipient} returned no response')
        return result
    async def publish(self,e): await asyncio.gather(*(h(e) for h in self._subscribers.get(e.recipient,[])))
