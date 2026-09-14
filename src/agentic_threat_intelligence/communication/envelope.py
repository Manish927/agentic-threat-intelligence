from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4
from .enums import MessageType, Sensitivity

@dataclass(frozen=True)
class AgentEnvelope:
    message_id: str; correlation_id: str; causation_id: str|None; case_id: str
    sender: str; recipient: str; message_type: MessageType; schema_version: str
    timestamp: datetime; sensitivity: Sensitivity; trace_id: str
    payload: Mapping[str,Any]; metadata: Mapping[str,Any]=field(default_factory=dict)
    hop_count: int=0; max_hops: int=12
    @classmethod
    def request(cls, *, case_id, sender, recipient, schema_version, trace_id, payload, sensitivity=Sensitivity.INTERNAL):
        mid=str(uuid4()); return cls(mid,mid,None,case_id,sender,recipient,MessageType.REQUEST,schema_version,datetime.now(timezone.utc),sensitivity,trace_id,dict(payload))
    def reply(self, *, sender, payload, message_type=MessageType.RESPONSE):
        if self.hop_count+1>self.max_hops: raise RuntimeError('Agent message hop limit exceeded')
        return AgentEnvelope(str(uuid4()),self.correlation_id,self.message_id,self.case_id,sender,self.sender,message_type,self.schema_version,datetime.now(timezone.utc),self.sensitivity,self.trace_id,dict(payload),hop_count=self.hop_count+1,max_hops=self.max_hops)
