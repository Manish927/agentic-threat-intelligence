from dataclasses import dataclass
from time import monotonic
from .registry import CapabilityRegistry
@dataclass
class Lease: capability:object; expires_at:float
class DynamicDiscoveryService:
    def __init__(self,registry:CapabilityRegistry): self.registry=registry; self._leases={}
    def announce(self,capability,ttl_seconds=60.0):
        k=f'{capability.agent_name}:{capability.version}'; self.registry.register(capability); self._leases[k]=Lease(capability,monotonic()+ttl_seconds)
    def reap_expired(self):
        now=monotonic()
        for k in [k for k,v in self._leases.items() if v.expires_at<=now]:
            lease=self._leases.pop(k); self.registry.unregister(lease.capability.agent_name,lease.capability.version)
