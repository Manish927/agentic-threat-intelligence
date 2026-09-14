from dataclasses import dataclass
from typing import Any, Mapping, Protocol
class DisclosurePolicy(Protocol):
    def filter_payload(self, *, recipient:str, payload:Mapping[str,Any])->Mapping[str,Any]: ...
@dataclass(frozen=True)
class AllowListDisclosurePolicy:
    allowed_fields_by_recipient: Mapping[str,frozenset[str]]
    def filter_payload(self, *, recipient, payload):
        allowed=self.allowed_fields_by_recipient.get(recipient,frozenset()); return {k:v for k,v in payload.items() if k in allowed}
DEFAULT_DISCLOSURE_POLICY=AllowListDisclosurePolicy({
'message-intelligence':frozenset({'subject','sanitized_body','sender','language_features'}),
'threat-intelligence':frozenset({'urls','domains','ip_addresses','file_hashes'}),
'risk-triage':frozenset({'ml_evidence','security_evidence','agent_findings'}),
'explainability':frozenset({'final_evidence','routing_decision','policy_reason'})})
