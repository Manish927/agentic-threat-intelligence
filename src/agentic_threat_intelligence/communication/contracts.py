from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
@dataclass(frozen=True)
class EvidenceRef:
    evidence_id:str; source:str; evidence_type:str; created_at_iso:str
@dataclass(frozen=True)
class AgentFinding:
    finding_type:str; summary:str; confidence:float
    evidence_refs:Sequence[EvidenceRef]=field(default_factory=tuple)
    attributes:Mapping[str,Any]=field(default_factory=dict)
@dataclass(frozen=True)
class AgentRequest:
    task:str; input_contract:str; data:Mapping[str,Any]
@dataclass(frozen=True)
class AgentResult:
    task:str; output_contract:str; findings:Sequence[AgentFinding]
    recommendation:str|None=None; confidence:float|None=None
    attributes:Mapping[str,Any]=field(default_factory=dict)
@dataclass(frozen=True)
class AgentError:
    category:str; message:str; retryable:bool; details:Mapping[str,Any]=field(default_factory=dict)
