from agentic_threat_intelligence.communication.security import DEFAULT_DISCLOSURE_POLICY

def test_threat_intel_only_gets_indicators():
    out=DEFAULT_DISCLOSURE_POLICY.filter_payload(recipient='threat-intelligence',payload={'subject':'x','sanitized_body':'y','urls':['u'],'domains':['d']})
    assert 'urls' in out and 'domains' in out and 'subject' not in out and 'sanitized_body' not in out
