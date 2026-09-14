from agentic_threat_intelligence.communication.envelope import AgentEnvelope

def test_reply_keeps_correlation():
    q=AgentEnvelope.request(case_id='c',sender='o',recipient='message-intelligence',schema_version='v1',trace_id='t',payload={'subject':'hi'})
    a=q.reply(sender='message-intelligence',payload={'ok':True})
    assert a.correlation_id==q.correlation_id and a.causation_id==q.message_id
