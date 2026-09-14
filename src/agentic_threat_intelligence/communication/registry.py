from .capability import AgentCapability
class CapabilityNotFound(LookupError): pass
class CapabilityRegistry:
    def __init__(self): self._items={}
    def register(self,c): self._items[f'{c.agent_name}:{c.version}']=c
    def unregister(self,name,version): self._items.pop(f'{name}:{version}',None)
    def list(self): return list(self._items.values())
    def find_by_task(self,task): return sorted([c for c in self._items.values() if task in c.supported_tasks], key=lambda c:c.priority)
    def resolve(self,task):
        m=self.find_by_task(task)
        if not m: raise CapabilityNotFound(f'No agent supports task: {task}')
        return m[0]
